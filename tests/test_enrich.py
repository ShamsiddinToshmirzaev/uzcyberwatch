"""app/enrich/ modullari uchun sinovlar (TZ: FT-15..20, NFT-11).

Barcha tashqi chaqiruvlar (geoip2, whois, ssl, httpx, imagehash) mock qilinadi —
haqiqiy tarmoq so'rovlari yo'q.
"""
from __future__ import annotations

import asyncio
import datetime
import io
import ssl
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from app.enrich import geoip, whois_lookup, cert, screenshot, reputation, pipeline


# ----------------------------------------------------------------- yordamchi

def _run(coro):
    """Async coroutineni sinxron test kontekstida bajaradi."""
    return asyncio.run(coro)


# ================================================================= FT-15: GeoIP

class TestGeoipIsPublic:
    def test_public_ip_true(self):
        assert geoip._is_public("8.8.8.8") is True
        assert geoip._is_public("195.158.7.1") is True

    def test_private_ip_false(self):
        assert geoip._is_public("192.168.1.1") is False
        assert geoip._is_public("10.0.0.1") is False
        assert geoip._is_public("127.0.0.1") is False

    def test_invalid_ip_false(self):
        assert geoip._is_public("not-an-ip") is False
        assert geoip._is_public("") is False


class TestGeoipLookup:
    def _mock_city_reader(self):
        reader = MagicMock()
        r = MagicMock()
        r.country.iso_code = "UZ"
        r.subdivisions.most_specific.name = "Toshkent"
        reader.__enter__ = MagicMock(return_value=reader)
        reader.__exit__ = MagicMock(return_value=False)
        reader.city.return_value = r
        return reader

    def _mock_asn_reader(self):
        reader = MagicMock()
        r = MagicMock()
        r.autonomous_system_number = 197522
        r.autonomous_system_organization = "UZTELECOM"
        reader.__enter__ = MagicMock(return_value=reader)
        reader.__exit__ = MagicMock(return_value=False)
        reader.asn.return_value = r
        return reader

    @patch("app.enrich.geoip.geoip2.database.Reader")
    def test_lookup_public_ip_success(self, mock_reader_cls):
        city_reader = self._mock_city_reader()
        asn_reader = self._mock_asn_reader()
        mock_reader_cls.side_effect = [city_reader, asn_reader]

        result = geoip._sync_lookup("195.158.7.1")
        assert result is not None
        assert result.ip == "195.158.7.1"
        assert result.geo_country == "UZ"
        assert result.geo_region == "Toshkent"
        assert result.asn == "AS197522"
        assert result.asn_org == "UZTELECOM"

    def test_lookup_private_ip_returns_none(self):
        result = geoip._sync_lookup("192.168.1.1")
        assert result is None

    @patch("app.enrich.geoip.geoip2.database.Reader", side_effect=FileNotFoundError)
    def test_lookup_no_db_file_returns_empty_result(self, _):
        result = geoip._sync_lookup("8.8.8.8")
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.geo_country is None
        assert result.asn is None

    @patch("app.enrich.geoip.geoip2.database.Reader")
    def test_lookup_address_not_found(self, mock_reader_cls):
        import geoip2.errors
        reader = MagicMock()
        reader.__enter__ = MagicMock(return_value=reader)
        reader.__exit__ = MagicMock(return_value=False)
        reader.city.side_effect = geoip2.errors.AddressNotFoundError("not found")
        reader.asn.side_effect = geoip2.errors.AddressNotFoundError("not found")
        mock_reader_cls.return_value = reader

        result = geoip._sync_lookup("8.8.8.8")
        assert result is not None
        assert result.geo_country is None

    @patch("app.enrich.geoip._sync_lookup")
    def test_async_lookup_calls_sync(self, mock_sync):
        mock_sync.return_value = geoip.GeoResult(ip="1.2.3.4", geo_country="UZ")
        result = _run(geoip.async_lookup("1.2.3.4"))
        mock_sync.assert_called_once_with("1.2.3.4")
        assert result.geo_country == "UZ"


# ================================================================= FT-16: WHOIS

class TestWhoisParseDate:
    def test_datetime_passthrough(self):
        dt = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        assert whois_lookup._parse_date(dt) == dt

    def test_list_takes_first(self):
        dt = datetime.datetime(2019, 6, 15, tzinfo=datetime.timezone.utc)
        result = whois_lookup._parse_date([dt, datetime.datetime(2020, 1, 1)])
        assert result == dt

    def test_none_returns_none(self):
        assert whois_lookup._parse_date(None) is None

    def test_invalid_type_returns_none(self):
        assert whois_lookup._parse_date(12345) is None


class TestWhoisSyncLookup:
    @patch("app.enrich.whois_lookup.pywhois.whois")
    def test_returns_registrar_and_age(self, mock_whois):
        creation = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        w = MagicMock()
        w.registrar = "RU-CENTER"
        w.creation_date = creation
        mock_whois.return_value = w

        result = whois_lookup._sync_lookup("example.uz")
        assert result.registrar == "RU-CENTER"
        assert result.domain_age_days is not None
        assert result.domain_age_days > 0

    @patch("app.enrich.whois_lookup.pywhois.whois")
    def test_registrar_as_list(self, mock_whois):
        w = MagicMock()
        w.registrar = ["RU-CENTER", "SECONDARY"]
        w.creation_date = None
        mock_whois.return_value = w

        result = whois_lookup._sync_lookup("example.uz")
        assert result.registrar == "RU-CENTER"

    @patch("app.enrich.whois_lookup.pywhois.whois", side_effect=Exception("timeout"))
    def test_exception_returns_empty_result(self, _):
        result = whois_lookup._sync_lookup("error.uz")
        assert result.registrar is None
        assert result.domain_age_days is None

    @patch("app.enrich.whois_lookup.pywhois.whois")
    def test_null_creation_date_domain_age_none(self, mock_whois):
        w = MagicMock()
        w.registrar = "TEST"
        w.creation_date = None
        mock_whois.return_value = w

        result = whois_lookup._sync_lookup("example.uz")
        assert result.domain_age_days is None

    @patch("app.enrich.whois_lookup._sync_lookup")
    def test_async_lookup_uses_thread(self, mock_sync):
        mock_sync.return_value = whois_lookup.WhoisResult(registrar="TEST", domain_age_days=500)
        result = _run(whois_lookup.lookup("example.uz"))
        mock_sync.assert_called_once_with("example.uz")
        assert result.registrar == "TEST"


# ================================================================= FT-17: SSL cert

class TestCert:
    @patch("app.enrich.cert.socket.create_connection")
    @patch("app.enrich.cert.ssl.create_default_context")
    def test_returns_issuer_org(self, mock_ctx_cls, mock_conn):
        ctx = MagicMock()
        tls = MagicMock()
        tls.getpeercert.return_value = {
            "issuer": [[("organizationName", "Let's Encrypt")], [("commonName", "R3")]]
        }
        ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls)
        ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ctx_cls.return_value = ctx
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = cert._sync_get_cert_issuer("example.uz")
        assert result == "Let's Encrypt"

    @patch("app.enrich.cert.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_connection_refused_returns_none(self, _):
        result = cert._sync_get_cert_issuer("offline.uz")
        assert result is None

    @patch("app.enrich.cert.socket.create_connection", side_effect=TimeoutError)
    def test_timeout_returns_none(self, _):
        result = cert._sync_get_cert_issuer("slow.uz")
        assert result is None

    @patch("app.enrich.cert._sync_get_cert_issuer")
    def test_async_uses_thread(self, mock_sync):
        mock_sync.return_value = "DigiCert Inc"
        result = _run(cert.get_cert_issuer("example.uz"))
        mock_sync.assert_called_once_with("example.uz", 443)
        assert result == "DigiCert Inc"

    @patch("app.enrich.cert._sync_get_cert_issuer")
    def test_async_custom_port(self, mock_sync):
        mock_sync.return_value = None
        _run(cert.get_cert_issuer("example.uz", port=8443))
        mock_sync.assert_called_once_with("example.uz", 8443)


# ================================================================= FT-18: pHash

class TestExtractImageUrl:
    def test_og_image_extracted(self):
        html = '<meta property="og:image" content="https://example.uz/img.png">'
        url = screenshot._extract_image_url(html, "https://example.uz")
        assert url == "https://example.uz/img.png"

    def test_og_image_reversed_attrs(self):
        html = '<meta content="https://example.uz/logo.jpg" property="og:image">'
        url = screenshot._extract_image_url(html, "https://example.uz")
        assert url == "https://example.uz/logo.jpg"

    def test_img_tag_fallback(self):
        html = '<img src="/images/banner.jpg" alt="test">'
        url = screenshot._extract_image_url(html, "https://example.uz")
        assert url == "https://example.uz/images/banner.jpg"

    def test_no_image_returns_none(self):
        html = "<html><body><p>Matn</p></body></html>"
        url = screenshot._extract_image_url(html, "https://example.uz")
        assert url is None

    def test_relative_url_resolved(self):
        html = '<img src="banner.jpg">'
        url = screenshot._extract_image_url(html, "https://example.uz/page/")
        assert url == "https://example.uz/page/banner.jpg"


class TestComputePhash:
    def _make_image_bytes(self) -> bytes:
        from PIL import Image
        img = Image.new("RGB", (8, 8), color=(128, 64, 32))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    @patch("app.enrich.screenshot.httpx.AsyncClient")
    def test_direct_image_url(self, mock_client_cls):
        img_bytes = self._make_image_bytes()

        mock_resp = MagicMock()
        mock_resp.content = img_bytes
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = _run(screenshot.compute_phash("https://example.uz/img.png"))
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    @patch("app.enrich.screenshot.httpx.AsyncClient")
    def test_html_with_og_image(self, mock_client_cls):
        img_bytes = self._make_image_bytes()
        html_resp = MagicMock()
        html_resp.text = '<meta property="og:image" content="https://example.uz/img.png">'
        html_resp.raise_for_status = MagicMock()

        img_resp = MagicMock()
        img_resp.content = img_bytes
        img_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[html_resp, img_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = _run(screenshot.compute_phash("https://example.uz"))
        assert result is not None

    @patch("app.enrich.screenshot.httpx.AsyncClient")
    def test_html_without_image_returns_none(self, mock_client_cls):
        html_resp = MagicMock()
        html_resp.text = "<html><body>Matn</body></html>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=html_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = _run(screenshot.compute_phash("https://example.uz"))
        assert result is None

    @patch("app.enrich.screenshot.httpx.AsyncClient")
    def test_network_error_returns_none(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("tarmoq xatosi"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = _run(screenshot.compute_phash("https://example.uz"))
        assert result is None


# ================================================================= FT-19: Reputatsiya

class TestReputationUrl:
    @patch.dict("os.environ", {"REPUTATION_VT_KEY": ""})
    def test_no_api_key_returns_empty(self):
        # Modul reload qilinmaydi — to'g'ridan-to'g'ri env ni tekshiramiz
        with patch("app.enrich.reputation.VT_KEY", ""):
            result = _run(reputation.lookup_url("http://example.uz"))
        assert result == {}

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_vt_success_returns_stats(self, mock_client_cls):
        vt_resp = MagicMock()
        vt_resp.status_code = 200
        vt_resp.json.return_value = {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60},
                "reputation": -5,
            }}
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=vt_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "test-key-123"):
            result = _run(reputation.lookup_url("http://phish.uz"))

        assert result["vt_malicious"] == 3
        assert result["vt_suspicious"] == 1
        assert result["vt_reputation"] == -5

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_vt_error_status_returns_empty(self, mock_client_cls):
        vt_resp = MagicMock()
        vt_resp.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=vt_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "test-key"):
            result = _run(reputation.lookup_url("http://unknown.uz"))

        assert result == {}

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_network_exception_returns_empty(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "test-key"):
            result = _run(reputation.lookup_url("http://phish.uz"))

        assert result == {}


class TestReputationIp:
    def test_no_keys_returns_empty(self):
        with patch("app.enrich.reputation.VT_KEY", ""), \
             patch("app.enrich.reputation.ABUSEIPDB_KEY", ""):
            result = _run(reputation.lookup_ip("8.8.8.8"))
        assert result == {}

    @patch("app.enrich.reputation._vt_ip")
    @patch("app.enrich.reputation._abuseipdb")
    def test_both_sources_merged(self, mock_abuse, mock_vt):
        mock_vt.return_value = {"vt_malicious": 2}
        mock_abuse.return_value = {"abuse_score": 75}

        with patch("app.enrich.reputation.VT_KEY", "k1"), \
             patch("app.enrich.reputation.ABUSEIPDB_KEY", "k2"):
            result = _run(reputation.lookup_ip("1.2.3.4"))

        assert result["vt_malicious"] == 2
        assert result["abuse_score"] == 75

    @patch("app.enrich.reputation._vt_ip")
    def test_partial_failure_ignored(self, mock_vt):
        mock_vt.return_value = {"vt_malicious": 1}

        with patch("app.enrich.reputation.VT_KEY", "k1"), \
             patch("app.enrich.reputation.ABUSEIPDB_KEY", ""):
            result = _run(reputation.lookup_ip("1.2.3.4"))

        assert "vt_malicious" in result


# ================================================================= FT-20: Pipeline

class TestPipeline:
    @patch("app.enrich.pipeline.geoip._sync_lookup")
    @patch("app.enrich.pipeline.whois_lookup._sync_lookup")
    @patch("app.enrich.pipeline.cert._sync_get_cert_issuer")
    @patch("app.enrich.pipeline.screenshot.compute_phash")
    @patch("app.enrich.pipeline.reputation.lookup_url")
    @patch("app.enrich.pipeline.reputation.lookup_ip")
    @patch("app.enrich.pipeline._resolve_ip")
    def test_full_pipeline(self, mock_ip, mock_rep_ip, mock_rep_url,
                           mock_phash, mock_cert, mock_whois, mock_geo):
        mock_ip.return_value = "195.158.7.1"
        mock_geo.return_value = geoip.GeoResult(
            ip="195.158.7.1", geo_country="UZ", geo_region="Toshkent",
            asn="AS197522", asn_org="UZTELECOM"
        )
        mock_whois.return_value = whois_lookup.WhoisResult(
            registrar="RU-CENTER", domain_age_days=365
        )
        mock_cert.return_value = "Let's Encrypt"
        mock_phash.return_value = "aabbccdd11223344"
        mock_rep_url.return_value = {"vt_malicious": 0}
        mock_rep_ip.return_value = {"abuse_score": 0}

        result = _run(pipeline.enrich(url="https://kapitalbank.uz", domain="kapitalbank.uz"))

        assert result.ip == "195.158.7.1"
        assert result.geo_country == "UZ"
        assert result.geo_region == "Toshkent"
        assert result.asn == "AS197522"
        assert result.asn_org == "UZTELECOM"
        assert result.registrar == "RU-CENTER"
        assert result.domain_age_days == 365
        assert result.cert_issuer == "Let's Encrypt"
        assert result.screenshot_phash == "aabbccdd11223344"
        assert "vt_malicious" in result.reputation

    @patch("app.enrich.pipeline._resolve_ip")
    def test_no_domain_returns_empty(self, mock_ip):
        result = _run(pipeline.enrich())
        assert result.ip is None
        assert result.geo_country is None
        mock_ip.assert_not_called()

    @patch("app.enrich.pipeline.geoip._sync_lookup", side_effect=Exception("DB yo'q"))
    @patch("app.enrich.pipeline.whois_lookup._sync_lookup")
    @patch("app.enrich.pipeline.cert._sync_get_cert_issuer", return_value=None)
    @patch("app.enrich.pipeline.screenshot.compute_phash")
    @patch("app.enrich.pipeline.reputation.lookup_url")
    @patch("app.enrich.pipeline.reputation.lookup_ip")
    @patch("app.enrich.pipeline._resolve_ip", return_value="1.2.3.4")
    def test_geoip_failure_doesnt_crash_pipeline(
        self, mock_ip, mock_rep_ip, mock_rep_url, mock_phash,
        mock_cert, mock_whois, mock_geo
    ):
        mock_whois.return_value = whois_lookup.WhoisResult(registrar="TEST", domain_age_days=100)
        mock_phash.return_value = None
        mock_rep_url.return_value = {}
        mock_rep_ip.return_value = {}

        result = _run(pipeline.enrich(url="https://test.uz"))
        assert result.geo_country is None
        assert result.registrar == "TEST"

    @patch("app.enrich.pipeline._resolve_ip", return_value=None)
    @patch("app.enrich.pipeline.whois_lookup._sync_lookup")
    @patch("app.enrich.pipeline.cert._sync_get_cert_issuer", return_value=None)
    @patch("app.enrich.pipeline.screenshot.compute_phash", return_value=None)
    @patch("app.enrich.pipeline.reputation.lookup_url", return_value={})
    def test_no_ip_skips_geo_and_ip_rep(
        self, mock_rep, mock_phash, mock_cert, mock_whois, mock_ip
    ):
        mock_whois.return_value = whois_lookup.WhoisResult()
        result = _run(pipeline.enrich(url="https://example.uz"))
        assert result.ip is None

    @patch("app.enrich.pipeline._resolve_ip", return_value="1.2.3.4")
    @patch("app.enrich.pipeline.geoip._sync_lookup")
    @patch("app.enrich.pipeline.whois_lookup._sync_lookup")
    @patch("app.enrich.pipeline.cert._sync_get_cert_issuer", return_value=None)
    @patch("app.enrich.pipeline.screenshot.compute_phash", return_value=None)
    @patch("app.enrich.pipeline.reputation.lookup_url", return_value={})
    @patch("app.enrich.pipeline.reputation.lookup_ip", return_value={})
    def test_domain_extracted_from_url(
        self, mock_rep_ip, mock_rep_url, mock_phash, mock_cert,
        mock_whois, mock_geo, mock_ip
    ):
        mock_geo.return_value = None
        mock_whois.return_value = whois_lookup.WhoisResult(registrar="RUCENTER", domain_age_days=200)

        _run(pipeline.enrich(url="https://kapitalbank.uz/login"))
        # whois domenni URLdan ajratib olishi kerak
        mock_whois.assert_called_once_with("kapitalbank.uz")

    def test_enrich_result_fields_complete(self):
        r = pipeline.EnrichResult()
        expected_fields = {
            "ip", "asn", "asn_org", "geo_country", "geo_region",
            "domain_age_days", "registrar", "cert_issuer",
            "screenshot_phash", "reputation",
        }
        assert expected_fields == set(vars(r).keys())


# ================================================================= FT-19: _vt_ip va _abuseipdb (qo'shimcha qamov)

class TestVtIpDirect:
    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_vt_ip_success(self, mock_client_cls):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 5},
                "reputation": -10,
            }}
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "k"):
            result = _run(reputation._vt_ip("1.2.3.4"))

        assert result["vt_malicious"] == 5
        assert result["vt_reputation"] == -10

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_vt_ip_non200_returns_empty(self, mock_client_cls):
        resp = MagicMock()
        resp.status_code = 429
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "k"):
            result = _run(reputation._vt_ip("1.2.3.4"))
        assert result == {}

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_vt_ip_exception_returns_empty(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.VT_KEY", "k"):
            result = _run(reputation._vt_ip("1.2.3.4"))
        assert result == {}


class TestAbuseIpdbDirect:
    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_abuseipdb_success(self, mock_client_cls):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 42,
            }
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.ABUSEIPDB_KEY", "k"):
            result = _run(reputation._abuseipdb("1.2.3.4"))

        assert result["abuse_score"] == 87
        assert result["abuse_reports"] == 42

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_abuseipdb_non200_returns_empty(self, mock_client_cls):
        resp = MagicMock()
        resp.status_code = 403
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.ABUSEIPDB_KEY", "k"):
            result = _run(reputation._abuseipdb("1.2.3.4"))
        assert result == {}

    @patch("app.enrich.reputation.httpx.AsyncClient")
    def test_abuseipdb_exception_returns_empty(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with patch("app.enrich.reputation.ABUSEIPDB_KEY", "k"):
            result = _run(reputation._abuseipdb("1.2.3.4"))
        assert result == {}
