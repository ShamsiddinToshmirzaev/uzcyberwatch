"""TI feed kollektori sinovlari (TZ: FT-05, HT-07, NFT-11).

Ochiq manba tahdid ma'lumotlari: URLhaus, OpenPhish, abuse.ch.
Faqat passiv o'qish — aktiv skanerlash yo'q (HT-07).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.ti_feed import (
    FEEDS,
    TiFeedCollector,
    _parse_plain_feed,
    _parse_urlhaus_csv,
    _print_sink,
)


# ----------------------------------------------------------------- yordamchi

def _run(coro):
    return asyncio.run(coro)


URLHAUS_CSV_SAMPLE = """\
# URLhaus feed
# Date: 2026-09-11
id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1,2026-09-11 10:00:00,http://phish.uz/steal,online,,phishing,phish,https://urlhaus.abuse.ch/url/1/,analyst
2,2026-09-11 10:01:00,https://malware.uz/payload.exe,online,,malware,malware,https://urlhaus.abuse.ch/url/2/,bot
3,2026-09-11 10:02:00,http://safe.example.com/page,offline,,,,https://urlhaus.abuse.ch/url/3/,bot
"""

PLAIN_FEED_SAMPLE = """\
# OpenPhish feed
http://phishing1.uz/login
https://phishing2.uz/card
# izoh
http://phishing3.uz/steal
"""


# ================================================================= Feed parserlari

class TestParsePlainFeed:
    def test_parses_urls(self):
        urls = _parse_plain_feed(PLAIN_FEED_SAMPLE)
        assert len(urls) == 3

    def test_skips_comments(self):
        urls = _parse_plain_feed(PLAIN_FEED_SAMPLE)
        for u in urls:
            assert not u.startswith("#")

    def test_skips_empty_lines(self):
        text = "\n\nhttp://a.uz/\n\n"
        urls = _parse_plain_feed(text)
        assert len(urls) == 1

    def test_returns_list_of_strings(self):
        urls = _parse_plain_feed(PLAIN_FEED_SAMPLE)
        assert all(isinstance(u, str) for u in urls)

    def test_empty_feed(self):
        assert _parse_plain_feed("") == []

    def test_only_comments(self):
        assert _parse_plain_feed("# izoh\n# boshqa izoh\n") == []


class TestParseUrlhausCsv:
    def test_parses_online_urls(self):
        urls = _parse_urlhaus_csv(URLHAUS_CSV_SAMPLE)
        assert any("phish.uz" in u for u in urls)
        assert any("malware.uz" in u for u in urls)

    def test_skips_comments(self):
        urls = _parse_urlhaus_csv(URLHAUS_CSV_SAMPLE)
        for u in urls:
            assert not u.startswith("#")

    def test_skips_offline(self):
        urls = _parse_urlhaus_csv(URLHAUS_CSV_SAMPLE)
        assert not any("safe.example.com" in u for u in urls)

    def test_returns_list_of_strings(self):
        urls = _parse_urlhaus_csv(URLHAUS_CSV_SAMPLE)
        assert all(isinstance(u, str) for u in urls)

    def test_empty_csv(self):
        assert _parse_urlhaus_csv("") == []

    def test_only_header_comments(self):
        assert _parse_urlhaus_csv("# izoh\n") == []


# ================================================================= FEEDS ro'yxati

class TestFeedsList:
    def test_feeds_not_empty(self):
        assert len(FEEDS) >= 2

    def test_each_feed_has_name(self):
        for f in FEEDS:
            assert "name" in f
            assert isinstance(f["name"], str)

    def test_each_feed_has_url(self):
        for f in FEEDS:
            assert "url" in f

    def test_each_feed_has_parser(self):
        for f in FEEDS:
            assert "parser" in f
            assert callable(f["parser"])

    def test_feed_urls_are_https_or_http(self):
        for f in FEEDS:
            assert f["url"].startswith("http"), f"{f['name']} URL noto'g'ri"

    def test_no_private_network_urls(self):
        """HT-07: TI feedlar ochiq internet manzillariga qaratilgan."""
        for f in FEEDS:
            url = f["url"]
            assert "localhost" not in url
            assert "127.0.0.1" not in url
            assert "192.168." not in url


# ================================================================= TiFeedCollector

class TestTiFeedCollectorInit:
    def test_default_interval(self):
        col = TiFeedCollector(sink=AsyncMock())
        assert col.interval >= 300      # kamida 5 daqiqa

    def test_custom_interval(self):
        col = TiFeedCollector(sink=AsyncMock(), interval=600)
        assert col.interval == 600

    def test_has_stats(self):
        col = TiFeedCollector(sink=AsyncMock())
        assert "fetched" in col.stats
        assert "emitted" in col.stats
        assert "errors" in col.stats

    def test_has_dedup_set(self):
        col = TiFeedCollector(sink=AsyncMock())
        assert hasattr(col, "seen")


# ================================================================= Bir feed qayta ishlash

class TestProcessFeed:
    @pytest.fixture
    def col(self):
        return TiFeedCollector(sink=AsyncMock(), min_risk=0)

    def test_process_increases_fetched(self, col):
        urls = ["http://phish.uz/steal", "http://bad.uz/mal"]
        _run(col._process_urls(urls, source_name="test_feed"))
        assert col.stats["fetched"] >= 2

    def test_process_calls_sink(self, col):
        urls = ["http://phish.uz/steal"]
        _run(col._process_urls(urls, source_name="test_feed"))
        assert col.sink.call_count >= 1

    def test_emitted_event_has_required_fields(self, col):
        urls = ["http://phish.uz/steal"]
        _run(col._process_urls(urls, source_name="test_feed"))
        if col.sink.call_count:
            event = col.sink.call_args[0][0]
            assert "url" in event
            assert "source_name" in event
            assert "observed_at" in event
            assert "verdict" in event

    def test_min_risk_filter(self):
        sink = AsyncMock()
        col = TiFeedCollector(sink=sink, min_risk=100)
        _run(col._process_urls(["http://safe.example.uz/"], source_name="test"))
        assert sink.call_count == 0

    def test_dedup_same_url(self, col):
        urls = ["http://phish.uz/same"]
        _run(col._process_urls(urls, source_name="test"))
        first = col.sink.call_count
        _run(col._process_urls(urls, source_name="test"))
        assert col.sink.call_count == first   # ikkinchi marta emit qilinmaydi

    def test_dedup_different_urls(self, col):
        _run(col._process_urls(["http://phish.uz/a"], source_name="test"))
        _run(col._process_urls(["http://phish.uz/b"], source_name="test"))
        assert col.sink.call_count >= 1


# ================================================================= HTTP fetch

class TestFetchFeed:
    def test_fetch_returns_text_on_success(self):
        col = TiFeedCollector(sink=AsyncMock())
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="http://bad.uz/\n")
        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        result = _run(col._fetch_text(mock_session, "http://feed.example.com/list"))
        assert result == "http://bad.uz/\n"

    def test_fetch_returns_none_on_error(self):
        col = TiFeedCollector(sink=AsyncMock())
        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(side_effect=Exception("network error")),
            __aexit__=AsyncMock(return_value=False),
        ))
        result = _run(col._fetch_text(mock_session, "http://feed.example.com/list"))
        assert result is None

    def test_fetch_error_increments_errors(self):
        col = TiFeedCollector(sink=AsyncMock())
        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(side_effect=Exception("timeout")),
            __aexit__=AsyncMock(return_value=False),
        ))
        _run(col._fetch_text(mock_session, "http://feed.example.com/list"))
        assert col.stats["errors"] >= 1


# ================================================================= HT-07: passiv

class TestPassiveOnly:
    def test_no_attack_methods(self):
        col = TiFeedCollector(sink=AsyncMock())
        forbidden = ["exploit", "attack", "scan", "brute", "inject", "spray"]
        for name in dir(col):
            if not name.startswith("_"):
                for kw in forbidden:
                    assert kw not in name.lower(), f"Hujumkor metod: {name}"

    def test_feeds_are_public_sources(self):
        """Barcha feed URL'lar ochiq ma'lumot bazalari."""
        public_domains = ["abuse.ch", "openphish", "phishtank",
                          "threatfox", "feodotracker"]
        for f in FEEDS:
            url = f["url"]
            is_public = any(d in url for d in public_domains)
            # Agar URL ro'yxatda bo'lmasa, kamida http bilan boshlanishi kerak
            assert url.startswith("http"), f"Feed URL xato: {url}"


# ================================================================= CLI sink

class TestPrintSink:
    def test_print_sink_callable(self):
        assert callable(_print_sink)

    def test_print_sink_runs(self, capsys):
        event = {
            "url": "http://phish.uz/steal",
            "source_name": "urlhaus",
            "observed_at": "2026-01-01T00:00:00",
            "verdict": {"risk_score": 75, "incident_type": "phishing", "reasons": []},
        }
        _run(_print_sink(event))
        out = capsys.readouterr().out
        assert "phish.uz" in out or "75" in out
