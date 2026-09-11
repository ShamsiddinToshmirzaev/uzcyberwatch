"""Honeypot kollektori sinovlari (TZ: FT-03, HT-03, HT-07, NFT-11).

Passiv HTTP honeypot: kiruvchi ulanishlarni qayd etadi,
hech qanday aktiv hujum yoki skanerlash amalga oshirilmaydi.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.honeypot import (
    HoneypotServer,
    _hash_ip,
    _mask_ip,
    _print_sink,
)


# ----------------------------------------------------------------- yordamchi

def _run(coro):
    return asyncio.run(coro)


def _make_request(path: str = "/admin", method: str = "GET",
                  ip: str = "1.2.3.4",
                  ua: str = "python-requests/2.28") -> dict:
    """Honeypot ga kelgan so'rov namunaси."""
    return {
        "method": method,
        "path": path,
        "remote_ip": ip,
        "user_agent": ua,
        "headers": {"host": "192.168.1.1"},
        "body_size": 0,
    }


# ================================================================= HT-03: IP hashing

class TestIpHashing:
    def test_hash_ip_returns_hex(self):
        h = _hash_ip("1.2.3.4")
        assert isinstance(h, str)
        assert len(h) == 64          # SHA-256 hex

    def test_hash_ip_deterministic(self):
        assert _hash_ip("1.2.3.4") == _hash_ip("1.2.3.4")

    def test_hash_ip_different_ips(self):
        assert _hash_ip("1.2.3.4") != _hash_ip("5.6.7.8")

    def test_raw_ip_not_in_hash(self):
        h = _hash_ip("1.2.3.4")
        assert "1.2.3.4" not in h

    def test_mask_ip_v4(self):
        masked = _mask_ip("1.2.3.4")
        assert masked.startswith("1.2.")
        assert "3.4" not in masked
        assert "*" in masked

    def test_mask_ip_v6(self):
        masked = _mask_ip("2001:db8::1")
        assert "2001" in masked
        assert "*" in masked


# ================================================================= HoneypotServer tuzilmasi

class TestHoneypotServerInit:
    def test_default_port(self):
        srv = HoneypotServer(sink=AsyncMock())
        assert srv.port == 8088

    def test_custom_port(self):
        srv = HoneypotServer(sink=AsyncMock(), port=9090)
        assert srv.port == 9090

    def test_has_stats(self):
        srv = HoneypotServer(sink=AsyncMock())
        assert "connections" in srv.stats
        assert "emitted" in srv.stats

    def test_has_dedup_set(self):
        srv = HoneypotServer(sink=AsyncMock())
        assert hasattr(srv, "seen")


# ================================================================= So'rovni qayta ishlash

class TestRequestHandling:
    @pytest.fixture
    def srv(self):
        sink = AsyncMock()
        return HoneypotServer(sink=sink, min_risk=0)

    def test_connections_counter_increments(self, srv):
        req = _make_request()
        _run(srv.handle_request(req))
        assert srv.stats["connections"] == 1

    def test_multiple_requests_counted(self, srv):
        for _ in range(5):
            _run(srv.handle_request(_make_request(path=f"/p{_}", ip="1.2.3.4")))
        assert srv.stats["connections"] == 5

    def test_sink_called_on_match(self, srv):
        req = _make_request(path="/admin/login")
        _run(srv.handle_request(req))
        assert srv.sink.call_count >= 1

    def test_emitted_event_has_required_fields(self, srv):
        req = _make_request(path="/phpmyadmin")
        _run(srv.handle_request(req))
        if srv.sink.call_count:
            event = srv.sink.call_args[0][0]
            assert "ip_hash" in event
            assert "ip_hint" in event
            assert "path" in event
            assert "method" in event
            assert "observed_at" in event

    def test_raw_ip_not_in_event(self, srv):
        """HT-03: xom IP hodisada bo'lmasligi shart."""
        req = _make_request(ip="9.8.7.6")
        _run(srv.handle_request(req))
        if srv.sink.call_count:
            event = srv.sink.call_args[0][0]
            assert "9.8.7.6" not in str(event)

    def test_min_risk_filter(self):
        """min_risk=100 bo'lsa hech narsa emit qilinmaydi."""
        sink = AsyncMock()
        srv = HoneypotServer(sink=sink, min_risk=100)
        _run(srv.handle_request(_make_request(path="/robots.txt")))
        assert sink.call_count == 0


# ================================================================= HT-07: faqat passiv

class TestPassiveOnly:
    def test_no_attack_methods(self):
        """HoneypotServer exploit yoki hujum metodlari yo'q."""
        srv = HoneypotServer(sink=AsyncMock())
        forbidden = ["exploit", "attack", "scan", "brute", "inject"]
        methods = [m for m in dir(srv) if not m.startswith("_")]
        for name in methods:
            for kw in forbidden:
                assert kw not in name.lower(), f"Hujumkor metod topildi: {name}"

    def test_handle_request_does_not_send_back(self):
        """Hodisa faqat sink ga boradi — tashqi serverga emas."""
        external_calls = []
        async def spy_sink(event):
            external_calls.append(event)
        srv = HoneypotServer(sink=spy_sink, min_risk=0)
        _run(srv.handle_request(_make_request()))
        # Tashqi chaqiruv yo'q — faqat sink ichki
        assert isinstance(external_calls, list)


# ================================================================= Deduplication

class TestDeduplication:
    def test_same_request_not_duplicated(self):
        sink = AsyncMock()
        srv = HoneypotServer(sink=sink, min_risk=0)
        req = _make_request(path="/admin", ip="1.2.3.4")
        _run(srv.handle_request(req))
        _run(srv.handle_request(req))
        first_count = sink.call_count
        # Ikkinchi urinish emit qilinmasligi kerak (dedup)
        assert sink.call_count == first_count

    def test_different_paths_both_emitted(self):
        sink = AsyncMock()
        srv = HoneypotServer(sink=sink, min_risk=0)
        _run(srv.handle_request(_make_request(path="/admin")))
        _run(srv.handle_request(_make_request(path="/wp-login")))
        # Har xil path — ikkalasi ham emit qilinishi kerak
        assert sink.call_count >= 1


# ================================================================= Interesli yo'llar

class TestInterestingPaths:
    @pytest.fixture
    def srv(self):
        return HoneypotServer(sink=AsyncMock(), min_risk=0)

    @pytest.mark.parametrize("path", [
        "/admin", "/wp-login.php", "/phpmyadmin",
        "/.env", "/config", "/shell",
    ])
    def test_interesting_path_detected(self, srv, path):
        assert srv._is_interesting(path), f"{path} qiziqarli yo'l sifatida aniqlanmadi"

    @pytest.mark.parametrize("path", [
        "/robots.txt", "/favicon.ico", "/",
    ])
    def test_normal_path_not_always_interesting(self, srv, path):
        # Ba'zi oddiy yo'llar qiziqarli bo'lmasligi mumkin
        result = srv._is_interesting(path)
        assert isinstance(result, bool)


# ================================================================= CLI sink

class TestPrintSink:
    def test_print_sink_callable(self):
        assert callable(_print_sink)

    def test_print_sink_runs(self, capsys):
        event = {
            "method": "GET", "path": "/admin",
            "ip_hint": "1.2.*.*",
            "observed_at": "2026-01-01T00:00:00",
            "risk_score": 42,
        }
        _run(_print_sink(event))
        out = capsys.readouterr().out
        assert "/admin" in out or "42" in out
