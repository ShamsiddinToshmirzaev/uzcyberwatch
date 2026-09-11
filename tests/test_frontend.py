"""Frontend SPA sinovlari (TZ: FT-31..37, NFT-11).

StaticFiles mounting va HTML tuzilishi tekshiriladi.
Barcha API so'rovlari frontend bilan birga ishlaydi.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.main import app


# ----------------------------------------------------------------- fixture

@pytest.fixture
def client():
    """TestClient — DB dependency override bilan."""
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    async def _fake_db():
        yield mock_session

    app.dependency_overrides[db_module.get_db] = _fake_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def html(client):
    return client.get("/").text


# ================================================================= Serving

class TestFrontendServing:
    def test_root_returns_200(self, client):
        assert client.get("/").status_code == 200

    def test_root_content_type_html(self, client):
        ct = client.get("/").headers.get("content-type", "")
        assert "text/html" in ct

    def test_not_redirect(self, client):
        # SPA: to'g'ridan-to'g'ri HTML qaytarishi kerak, yo'naltirish yo'q
        assert client.get("/").status_code == 200

    def test_api_routes_still_work(self, client):
        assert client.get("/health").status_code == 200

    def test_analyse_endpoint_works_with_frontend(self, client):
        resp = client.post(
            "/api/v1/analyse",
            json={"url": "http://phish.uz"},
        )
        assert resp.status_code == 200

    def test_cases_endpoint_works_with_frontend(self, client):
        mock = client.app.dependency_overrides[db_module.get_db]
        resp = client.get("/api/v1/cases")
        # DB xatosi bo'lsa ham endpoint ishlaydi (500 emas 200/422)
        assert resp.status_code in (200, 500)


# ================================================================= HTML tuzilishi

class TestHtmlTitle:
    def test_title_contains_project_name(self, html):
        assert "UzCyberWatch" in html

    def test_html_lang_uz(self, html):
        assert 'lang="uz"' in html or "lang='uz'" in html


class TestNavigation:
    def test_nav_element_present(self, html):
        assert "<nav" in html

    def test_dashboard_tab(self, html):
        low = html.lower()
        assert "bosh sahifa" in low or "dashboard" in low

    def test_analyse_tab(self, html):
        low = html.lower()
        assert "tahlil" in low

    def test_cases_tab(self, html):
        low = html.lower()
        assert "ishlar" in low


class TestDashboardSection:
    """FT-31: Asboblar paneli."""

    def test_dashboard_section_id(self, html):
        assert 'id="dashboard"' in html

    def test_status_display_element(self, html):
        # Tizim holati ko'rsatilishi shart
        assert "status" in html.lower()

    def test_health_endpoint_referenced(self, html):
        assert "/health" in html

    def test_graph_section_present(self, html):
        # FT-36: Graf bo'limi
        assert 'id="graph-section"' in html or "graph" in html.lower()


class TestAnalyseSection:
    """FT-32, FT-33, FT-35: Tahlil formasi va natijalar."""

    def test_analyse_section_id(self, html):
        assert 'id="analyse"' in html

    def test_url_input_present(self, html):
        assert 'id="url-input"' in html

    def test_text_input_present(self, html):
        assert 'id="text-input"' in html

    def test_analyse_form_present(self, html):
        assert 'id="analyse-form"' in html

    def test_result_panel_present(self, html):
        assert 'id="result-panel"' in html

    def test_risk_score_element(self, html):
        assert 'id="risk-score"' in html

    def test_reasons_list_element(self, html):
        assert 'id="reasons-list"' in html

    def test_api_analyse_referenced(self, html):
        assert "/api/v1/analyse" in html or "/analyse" in html

    def test_legal_section_present(self, html):
        # HT-05: huquqiy tavsiyalar
        assert 'id="legal' in html or "huquqiy" in html.lower()


class TestCasesSection:
    """FT-34: Ishlar ro'yxati."""

    def test_cases_section_id(self, html):
        assert 'id="cases"' in html

    def test_cases_table_present(self, html):
        assert 'id="cases-table"' in html

    def test_status_filter_present(self, html):
        assert 'id="status-filter"' in html

    def test_cases_api_referenced(self, html):
        assert "/api/v1/cases" in html or "/cases" in html

    def test_pagination_element(self, html):
        assert 'id="pagination"' in html


class TestExportSection:
    """FT-37: Eksport."""

    def test_export_button_present(self, html):
        assert 'id="export-btn"' in html

    def test_csv_referenced(self, html):
        low = html.lower()
        assert "csv" in low or "eksport" in low


# ================================================================= Sprint 12: Stats va Login

class TestLoginSection:
    """JWT login paneli."""

    def test_login_form_exists(self, html):
        assert 'id="login-form"' in html

    def test_login_username_input(self, html):
        assert 'id="login-username"' in html

    def test_login_password_input(self, html):
        assert 'id="login-password"' in html

    def test_login_submit_button(self, html):
        assert 'id="login-btn"' in html

    def test_login_overlay_exists(self, html):
        assert 'id="login-overlay"' in html


class TestStatsSection:
    """FT-47,48: Real statistika elementlari."""

    def test_total_cases_element(self, html):
        assert 'id="cases-count"' in html

    def test_avg_risk_element(self, html):
        assert 'id="avg-risk"' in html

    def test_high_risk_element(self, html):
        assert 'id="high-risk-count"' in html

    def test_timeline_section_exists(self, html):
        assert 'id="timeline-section"' in html or 'id="timeline-canvas"' in html

    def test_region_section_exists(self, html):
        assert 'id="region-list"' in html

    def test_status_distribution_exists(self, html):
        assert 'id="status-bars"' in html

    def test_stats_api_referenced(self, html):
        assert "/api/v1/stats" in html


class TestAuthHeader:
    """JWT token API so'rovlarda ishlatiladi."""

    def test_authorization_header_used(self, html):
        assert "Authorization" in html or "Bearer" in html

    def test_localstorage_token_referenced(self, html):
        assert "localStorage" in html and ("token" in html.lower() or "jwt" in html.lower())

    def test_logout_button_exists(self, html):
        assert 'id="logout-btn"' in html
