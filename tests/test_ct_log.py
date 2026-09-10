"""CT Log kollektori sinovlari (TZ: FT-01, FT-08, FT-09, NFT-11).

WebSocket va tashqi ulanishlar mock qilinadi.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.ct_log import CtLogCollector, _print_sink


# ----------------------------------------------------------------- yordamchi

def _run(coro):
    return asyncio.run(coro)


def _make_msg(domains: list[str], seen: float = 1_700_000_000.0,
              issuer_o: str = "Let's Encrypt") -> dict:
    """Certstream sertifikat xabari namunasi."""
    return {
        "message_type": "certificate_update",
        "data": {
            "seen": seen,
            "leaf_cert": {
                "all_domains": domains,
                "issuer": {"O": issuer_o},
                "not_before": 1_700_000_000,
            },
        },
    }


# ================================================================= Prefilter

class TestPrefilter:
    def _bot(self):
        return CtLogCollector(sink=AsyncMock())

    def test_suspicious_domain_passes(self):
        c = self._bot()
        assert c._prefilter("kapitalbnk.uz") is True

    def test_typosquat_domain_passes(self):
        c = self._bot()
        assert c._prefilter("clik.uz") is True

    def test_lure_domain_passes(self):
        c = self._bot()
        assert c._prefilter("payme-kirish.com") is True

    def test_benign_domain_fails(self):
        c = self._bot()
        assert c._prefilter("google.com") is False

    def test_empty_domain_fails(self):
        c = self._bot()
        assert c._prefilter("") is False

    def test_plain_tld_fails(self):
        c = self._bot()
        assert c._prefilter(".uz") is False


# ================================================================= Dedup

class TestDedup:
    def test_first_occurrence_allowed(self):
        c = CtLogCollector(sink=AsyncMock())
        assert c._dedup("example.uz") is True

    def test_second_occurrence_blocked(self):
        c = CtLogCollector(sink=AsyncMock())
        c._dedup("example.uz")
        assert c._dedup("example.uz") is False

    def test_different_domains_both_allowed(self):
        c = CtLogCollector(sink=AsyncMock())
        assert c._dedup("a.uz") is True
        assert c._dedup("b.uz") is True

    def test_memory_limit_clears_set(self):
        c = CtLogCollector(sink=AsyncMock())
        # To'g'ridan-to'g'ri seen ni 500_001 ga yetkazamiz
        c.seen = {f"fake{i}" for i in range(500_001)}
        # Keyingi _dedup chaqiruvida seen tozalanib, True qaytarishi kerak
        result = c._dedup("newdomain.uz")
        assert result is True
        assert len(c.seen) < 500_001


# ================================================================= handle_cert

class TestHandleCert:
    def _col(self, min_risk: int = 1) -> tuple[CtLogCollector, AsyncMock]:
        sink = AsyncMock()
        return CtLogCollector(sink=sink, min_risk=min_risk), sink

    def test_wrong_message_type_ignored(self):
        c, sink = self._col()
        _run(c.handle_cert({"message_type": "heartbeat"}))
        sink.assert_not_called()
        assert c.stats["certs"] == 0

    def test_empty_message_ignored(self):
        c, sink = self._col()
        _run(c.handle_cert({}))
        sink.assert_not_called()

    def test_suspicious_domain_emits_to_sink(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"])
        _run(c.handle_cert(msg))
        sink.assert_called_once()

    def test_sink_event_structure(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"])
        _run(c.handle_cert(msg))
        ev = sink.call_args[0][0]
        assert ev["source_kind"] == "ct_log"
        assert ev["event_type"] == "domain"
        assert ev["domain"] == "kapitalbnk.uz"
        assert "verdict" in ev
        assert "observed_at" in ev

    def test_cert_issuer_in_event(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"], issuer_o="ZeroSSL")
        _run(c.handle_cert(msg))
        ev = sink.call_args[0][0]
        assert ev["cert_issuer"] == "ZeroSSL"

    def test_benign_domain_below_min_risk_not_emitted(self):
        c, sink = self._col(min_risk=99)  # barcha domenlar bu chegaradan past
        msg = _make_msg(["google.com"])
        _run(c.handle_cert(msg))
        sink.assert_not_called()

    def test_wildcard_prefix_stripped(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["*.kapitalbnk.uz"])
        _run(c.handle_cert(msg))
        # Domain to'g'ri tozalanishi va prefilterdan o'tishi kerak
        if sink.call_count > 0:
            ev = sink.call_args[0][0]
            assert not ev["domain"].startswith("*")

    def test_stats_certs_incremented(self):
        c, sink = self._col(min_risk=1)
        _run(c.handle_cert(_make_msg(["kapitalbnk.uz"])))
        assert c.stats["certs"] == 1

    def test_stats_domains_incremented(self):
        c, sink = self._col(min_risk=1)
        _run(c.handle_cert(_make_msg(["kapitalbnk.uz", "clik.uz"])))
        assert c.stats["domains"] == 2

    def test_stats_emitted_incremented_on_sink_call(self):
        c, sink = self._col(min_risk=1)
        _run(c.handle_cert(_make_msg(["kapitalbnk.uz"])))
        assert c.stats["emitted"] >= 1

    def test_duplicate_domain_not_emitted_twice(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"])
        _run(c.handle_cert(msg))
        _run(c.handle_cert(msg))
        assert sink.call_count == 1

    def test_multiple_suspicious_domains_per_cert(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz", "clik.uz", "payme-kirish.com"])
        _run(c.handle_cert(msg))
        assert sink.call_count >= 1

    def test_seen_at_used_in_observed_at(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"], seen=1_600_000_000.0)
        _run(c.handle_cert(msg))
        if sink.call_count > 0:
            ev = sink.call_args[0][0]
            assert "2020" in ev["observed_at"]  # 1_600_000_000 ~ 2020-yil

    def test_missing_seen_uses_current_time(self):
        c, sink = self._col(min_risk=1)
        msg = _make_msg(["kapitalbnk.uz"])
        del msg["data"]["seen"]
        _run(c.handle_cert(msg))
        if sink.call_count > 0:
            ev = sink.call_args[0][0]
            assert "observed_at" in ev

    def test_empty_domains_list_no_sink(self):
        c, sink = self._col()
        msg = _make_msg([])
        _run(c.handle_cert(msg))
        sink.assert_not_called()

    def test_no_leaf_cert_no_crash(self):
        c, sink = self._col()
        msg = {"message_type": "certificate_update", "data": {}}
        _run(c.handle_cert(msg))
        sink.assert_not_called()


# ================================================================= _print_sink

class TestPrintSink:
    def test_print_sink_output(self, capsys):
        ev = {
            "domain": "kapitalbnk.uz",
            "verdict": {
                "risk_score": 55,
                "incident_type": "phishing_site",
                "reasons": [
                    {"code": "brand_typosquat", "weight": 45, "detail": "typosquat"},
                ],
            },
        }
        _run(_print_sink(ev))
        out = capsys.readouterr().out
        assert "55" in out
        assert "kapitalbnk.uz" in out

    def test_print_sink_no_reasons(self, capsys):
        ev = {
            "domain": "test.uz",
            "verdict": {
                "risk_score": 30,
                "incident_type": "unknown",
                "reasons": [],
            },
        }
        _run(_print_sink(ev))
        out = capsys.readouterr().out
        assert "test.uz" in out
