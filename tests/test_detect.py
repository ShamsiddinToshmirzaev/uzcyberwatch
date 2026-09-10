"""Aniqlash yadrosi uchun modul sinovlari (TZ: 6.2-band, NFT-11)."""
from __future__ import annotations

import pytest

from app.detect import brands, engine, legal_map, text_rules
from app.normalize import lang, pii


# ------------------------------------------------------------------ brendlar
@pytest.mark.parametrize("host,kind", [
    ("click.uz", "exact_official"),
    ("my.gov.uz", "exact_official"),
    ("clik.uz", "typosquat"),
    ("kapitalbnk.uz", "typosquat"),
    ("payme-kirish.net", "typosquat"),
    ("click.uz.tasdiqlash-hisob.com", "subdomain_abuse"),
    ("\u0441lick.uz", "homoglyph"),
])
def test_brand_kinds(host, kind):
    m = brands.match_host(host)
    assert m is not None and m.kind == kind


@pytest.mark.parametrize("host", ["google.com", "wikipedia.org", "example.net"])
def test_benign_hosts_not_flagged(host):
    assert brands.match_host(host) is None


def test_punycode_decoded():
    host = "\u0441lick".encode("idna").decode() + ".uz"
    m = brands.match_host(host)
    assert m and m.kind == "homoglyph" and m.brand == "click"


def test_official_domains_never_typosquat():
    for domains in brands.BRANDS.values():
        for d in domains:
            assert brands.match_host(d).kind == "exact_official"


# ------------------------------------------------------------------ til
@pytest.mark.parametrize("text,expected", [
    ("Kartangiz bloklandi, kodni yuboring", "uz-Latn"),
    ("\u041a\u0430\u0440\u0442\u0430\u043d\u0433\u0438\u0437 \u0431\u043b\u043e\u043a\u043b\u0430\u043d\u0434\u0438, \u043a\u043e\u0434\u043d\u0438 \u044e\u0431\u043e\u0440\u0438\u043d\u0433", "uz-Cyrl"),
    ("\u0412\u0430\u0448\u0430 \u043a\u0430\u0440\u0442\u0430 \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d\u0430", "ru"),
    ("Your account has been suspended", "en"),
])
def test_lang_detection(text, expected):
    assert lang.detect_lang(text) == expected


def test_cyrillic_and_latin_normalise_alike():
    a = lang.normalize_text("Kartangiz bloklandi")[1]
    b = lang.normalize_text("\u041a\u0430\u0440\u0442\u0430\u043d\u0433\u0438\u0437 \u0431\u043b\u043e\u043a\u043b\u0430\u043d\u0434\u0438")[1]
    assert a.lower() == b.lower()


# ------------------------------------------------------------------ PII
def test_card_requires_luhn():
    assert not any(h.kind == "card" for h in pii.scan("Karta 8600 1234 5678 9010"))
    assert any(h.kind == "card" for h in pii.scan("Karta 8600 1234 5678 9012"))


def test_phone_masked_and_hashed():
    hits = pii.scan("tel +998 90 123 45 67")
    phone = next(h for h in hits if h.kind == "phone")
    assert "123" not in phone.hint
    assert len(phone.hash) == 64


def test_hash_is_stable_across_formats():
    a = pii.pii_hash("phone", "+998 90 123 45 67")
    b = pii.pii_hash("phone", "998901234567")
    assert a == b


def test_redact_removes_raw_pii():
    out = pii.redact("karta 8600 1234 5678 9012 tel +998901234567")
    assert "8600" not in out and "901234567" not in out


# ------------------------------------------------------------------ matn
def test_agglutinative_suffixes_match():
    _, norm = lang.normalize_text("SMS kodni yuboring, kartangiz bloklandi")
    rules = {h.rule for h in text_rules.scan_text(norm)}
    assert "credential_request" in rules
    assert "card_block" in rules


@pytest.mark.parametrize("text", [
    "Ertaga majlis bo'ladi, hujjatlarni tayyorlang",
    "Salom, kitobni qaytarib bering",
])
def test_benign_text_no_hits(text):
    _, norm = lang.normalize_text(text)
    assert text_rules.scan_text(norm) == []


# ------------------------------------------------------------------ yadro
def test_official_domain_scores_zero():
    v = engine.analyse(url="https://click.uz/payment", domain_age_days=2900)
    assert v.risk_score == 0


def test_typosquat_with_fresh_domain_scores_high():
    v = engine.analyse(url="http://click-uz-tasdiqlash.xyz/login", domain_age_days=3)
    assert v.risk_score >= 60
    assert v.incident_type == "phishing_site"


def test_risk_never_exceeds_bounds():
    v = engine.analyse(
        url="http://xn--lick-k6d.uz.secure-login-kirish.xyz:8443/verify@x",
        text="SMS kodni yuboring, kartangiz bloklandi, hech kimga aytmang, jarima",
        domain_age_days=1,
        ml_score=0.99,
    )
    assert 0 <= v.risk_score <= 100
    assert 0.0 <= v.confidence <= 1.0


def test_every_reason_has_detail():
    v = engine.analyse(url="http://payme-bonus-olish.top/", domain_age_days=2)
    assert v.reasons
    assert all(r.detail and r.weight > 0 for r in v.reasons)


def test_legal_suggestion_requires_review():
    v = engine.analyse(url="http://uzcard-kirish.xyz/", domain_age_days=1)
    assert v.legal
    assert all(s["requires_review"] for s in v.legal)


def test_legal_confidence_scales_with_risk():
    low = legal_map.suggest("card_theft", 10)[0].confidence
    high = legal_map.suggest("card_theft", 95)[0].confidence
    assert high > low


def test_pii_never_returned_raw():
    v = engine.analyse(text="Kartam 8600 1234 5678 9012, tel +998901234567")
    for p in v.pii_found:
        assert "8600123456789012" not in p["hint"]
        assert len(p["hash"]) == 64
