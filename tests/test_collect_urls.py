"""ml/collect_urls.py sinovlari (TZ: QM-18, NFT-11).

Dataset yig'uvchi skriptning barcha funksiyalari va
QM-18 (≥20 000 namuna) talabi tekshiriladi.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from ml.collect_urls import (
    _free_tld,
    _lure_combo,
    _subdomain_abuse,
    _typosquat,
    build_dataset,
    generate_benign,
    generate_phishing,
    save_dataset,
)

_RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top",
               "buzz", "site", "online", "click", "rest"}


# ================================================================= _typosquat

class TestTyposquat:
    def test_returns_non_empty_list(self):
        assert len(_typosquat("kapitalbank")) > 0

    def test_all_strings(self):
        assert all(isinstance(s, str) for s in _typosquat("click"))

    def test_original_not_in_result(self):
        # "kapitalbank.uz" rasmiy domen — typosquat ro'yxatida bo'lmasligi kerak
        result = _typosquat("kapitalbank")
        assert "kapitalbank.uz" not in result

    def test_hyphenated_variants_present(self):
        result = _typosquat("kapitalbank")
        assert any("-" in r for r in result)

    def test_multiple_tlds(self):
        result = _typosquat("payme")
        tlds_seen = {r.rsplit(".", 1)[-1] for r in result if "." in r}
        assert len(tlds_seen) >= 2

    def test_short_brand(self):
        result = _typosquat("nbu")
        assert isinstance(result, list)

    def test_no_empty_strings(self):
        result = _typosquat("kapitalbank")
        assert all(r.strip() for r in result)


# ================================================================= _free_tld

class TestFreeTld:
    def test_returns_list(self):
        assert isinstance(_free_tld("kapitalbank"), list)

    def test_risky_tlds_used(self):
        result = _free_tld("kapitalbank")
        tlds = {r.rsplit(".", 1)[-1] for r in result}
        assert tlds & _RISKY_TLDS

    def test_brand_in_result(self):
        result = _free_tld("payme")
        assert any("payme" in r for r in result)


# ================================================================= _subdomain_abuse

class TestSubdomainAbuse:
    def test_returns_list(self):
        assert isinstance(_subdomain_abuse("kapitalbank", "uz"), list)

    def test_official_domain_in_subdomain(self):
        result = _subdomain_abuse("kapitalbank", "uz")
        assert any("kapitalbank" in r for r in result)

    def test_attacker_domain_present(self):
        result = _subdomain_abuse("kapitalbank", "uz")
        # Rasmiy domen "kapitalbank.uz.something.com" shaklida bo'lishi kerak
        assert any("kapitalbank.uz" in r and ".uz." in r for r in result)


# ================================================================= _lure_combo

class TestLureCombo:
    def test_returns_list(self):
        assert isinstance(_lure_combo("kapitalbank"), list)

    def test_lure_words_present(self):
        result = _lure_combo("kapitalbank")
        lure_words = {"login", "secure", "verify", "kirish", "pay", "confirm"}
        assert any(any(w in r for w in lure_words) for r in result)

    def test_brand_in_result(self):
        result = _lure_combo("payme")
        assert any("payme" in r for r in result)


# ================================================================= generate_phishing

class TestGeneratePhishing:
    def test_returns_list(self):
        assert isinstance(generate_phishing(), list)

    def test_count_at_least_5000(self):
        assert len(generate_phishing()) >= 5000

    def test_all_strings(self):
        assert all(isinstance(u, str) for u in generate_phishing())

    def test_contains_http_urls(self):
        assert any(u.startswith("http://") for u in generate_phishing())

    def test_contains_ip_based_urls(self):
        import re
        ip_pat = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        assert any(ip_pat.match(u) for u in generate_phishing())

    def test_deterministic_same_seed(self):
        r1 = generate_phishing(seed=42)
        r2 = generate_phishing(seed=42)
        assert sorted(r1) == sorted(r2)

    def test_different_seed_different_result(self):
        r1 = generate_phishing(seed=42)
        r2 = generate_phishing(seed=99)
        # Asosiy to'plam bir xil bo'lsa ham IP qismi farq qilishi kerak
        assert set(r1) != set(r2)

    def test_no_official_brand_domains(self):
        # Rasmiy domenlar (kapitalbank.uz) phishing sifatida belgilanmasligi kerak
        official = {"kapitalbank.uz", "click.uz", "payme.uz", "nbu.uz", "humo.uz"}
        urls = generate_phishing()
        for url in urls:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            assert host not in official, f"Rasmiy domen phishing sifatida: {url}"


# ================================================================= generate_benign

class TestGenerateBenign:
    def test_returns_list(self):
        assert isinstance(generate_benign(), list)

    def test_count_at_least_5000(self):
        assert len(generate_benign()) >= 5000

    def test_mostly_https(self):
        urls = generate_benign()
        https_ratio = sum(1 for u in urls if u.startswith("https://")) / len(urls)
        assert https_ratio >= 0.7

    def test_no_risky_tlds(self):
        urls = generate_benign()
        for url in urls:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            assert tld not in _RISKY_TLDS, f"Xavfli TLD yaxshi URLda: {url}"

    def test_no_ip_addresses(self):
        import re
        ip_pat = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        assert not any(ip_pat.match(u) for u in generate_benign())

    def test_deterministic(self):
        r1 = generate_benign(seed=42)
        r2 = generate_benign(seed=42)
        assert sorted(r1) == sorted(r2)


# ================================================================= build_dataset

class TestBuildDataset:
    def test_returns_list_of_tuples(self):
        rows = build_dataset()
        assert isinstance(rows, list)
        assert all(isinstance(r, tuple) and len(r) == 2 for r in rows)

    def test_qm18_total_count(self):
        rows = build_dataset()
        assert len(rows) >= 20_000, f"QM-18 bajarilmadi: {len(rows)} < 20000"

    def test_labels_are_binary(self):
        rows = build_dataset()
        labels = {r[1] for r in rows}
        assert labels == {0, 1}

    def test_both_classes_substantial(self):
        rows = build_dataset()
        phishing = sum(1 for _, l in rows if l == 1)
        benign   = sum(1 for _, l in rows if l == 0)
        assert phishing >= 5_000, f"Phishing kam: {phishing}"
        assert benign   >= 5_000, f"Benign kam: {benign}"

    def test_no_duplicate_urls(self):
        rows = build_dataset()
        urls = [r[0] for r in rows]
        assert len(urls) == len(set(urls)), "Takroriy URLlar topildi"

    def test_reasonable_class_balance(self):
        rows = build_dataset()
        ratio = sum(1 for _, l in rows if l == 1) / len(rows)
        assert 0.3 <= ratio <= 0.7, f"Nomutanosib: phishing {ratio:.1%}"

    def test_all_urls_non_empty(self):
        rows = build_dataset()
        assert all(r[0].strip() for r in rows)

    def test_all_labels_int(self):
        rows = build_dataset()
        assert all(isinstance(r[1], int) for r in rows)


# ================================================================= save_dataset

class TestSaveDataset:
    def test_saves_file(self, tmp_path):
        rows = [("http://phish.uz/login", 1), ("https://bank.uz/", 0)]
        save_dataset(tmp_path / "test.csv", rows)
        assert (tmp_path / "test.csv").exists()

    def test_csv_header(self, tmp_path):
        rows = [("http://phish.uz/login", 1)]
        path = tmp_path / "out.csv"
        save_dataset(path, rows)
        with path.open(encoding="utf-8") as f:
            header = f.readline().strip()
        assert header == "url,label"

    def test_csv_values(self, tmp_path):
        rows = [("http://phish.uz/login", 1), ("https://bank.uz/", 0)]
        path = tmp_path / "out.csv"
        save_dataset(path, rows)
        with path.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            data = list(reader)
        assert data[0]["url"] == "http://phish.uz/login"
        assert data[0]["label"] == "1"
        assert data[1]["label"] == "0"

    def test_returns_row_count(self, tmp_path):
        rows = [("http://a.com/", 1)] * 50
        n = save_dataset(tmp_path / "out.csv", rows)
        assert n == 50

    def test_creates_parent_dir(self, tmp_path):
        path = tmp_path / "subdir" / "urls.csv"
        save_dataset(path, [("http://x.com/", 1)])
        assert path.exists()


# ================================================================= QM-18 talabi

class TestQM18Compliance:
    def test_minimum_20000_records(self):
        """TZ QM-18: dataset kamida 20 000 namuna bo'lishi shart."""
        rows = build_dataset()
        assert len(rows) >= 20_000

    def test_phishing_at_least_8000(self):
        """Phishing namumalari yetarli bo'lishi shart."""
        rows = build_dataset()
        assert sum(1 for _, l in rows if l == 1) >= 8_000

    def test_benign_at_least_8000(self):
        """Yaxshi namumalari yetarli bo'lishi shart."""
        rows = build_dataset()
        assert sum(1 for _, l in rows if l == 0) >= 8_000

    def test_urls_parseable(self):
        """Barcha URLlar to'g'ri formatda bo'lishi shart."""
        from urllib.parse import urlparse
        rows = build_dataset()
        for url, _ in rows[:500]:  # birinchi 500 ni tekshirish
            p = urlparse(url)
            assert p.scheme in ("http", "https"), f"Noto'g'ri sxema: {url}"
            assert p.netloc, f"Host yo'q: {url}"
