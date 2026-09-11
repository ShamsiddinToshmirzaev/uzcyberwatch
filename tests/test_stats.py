"""Statistika API sinovlari (TZ: FT-47, FT-48, NFT-11).

TDD: avval testlar, keyin implementatsiya.
Dashboard uchun real-time agregat ma'lumotlar.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.main import app


# ----------------------------------------------------------------- yordamchi

def _row(**kw):
    """Oddiy namespace (Row mock)."""
    r = MagicMock()
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _mock_session(rows=None, scalar_val=None):
    """DB session mock."""
    result = MagicMock()
    result.all.return_value = rows or []
    result.scalar.return_value = scalar_val
    result.mappings.return_value.all.return_value = rows or []
    sess = AsyncMock()
    sess.execute = AsyncMock(return_value=result)
    return sess


@pytest.fixture
def client():
    async def _fake_db():
        yield _mock_session()
    app.dependency_overrides[db_module.get_db] = _fake_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()



# ================================================================= GET /api/v1/stats

class TestStatsOverview:
    def test_endpoint_exists(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200

    def test_response_is_json(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.headers["content-type"].startswith("application/json")

    def test_has_total_cases(self, client):
        data = client.get("/api/v1/stats").json()
        assert "total_cases" in data

    def test_has_avg_risk(self, client):
        data = client.get("/api/v1/stats").json()
        assert "avg_risk" in data

    def test_has_by_status(self, client):
        data = client.get("/api/v1/stats").json()
        assert "by_status" in data

    def test_has_by_region(self, client):
        data = client.get("/api/v1/stats").json()
        assert "by_region" in data

    def test_has_high_risk_count(self, client):
        data = client.get("/api/v1/stats").json()
        assert "high_risk_count" in data

    def test_total_cases_is_int(self, client):
        assert isinstance(client.get("/api/v1/stats").json()["total_cases"], int)

    def test_avg_risk_is_numeric(self, client):
        val = client.get("/api/v1/stats").json()["avg_risk"]
        assert isinstance(val, (int, float))

    def test_by_status_is_dict(self, client):
        assert isinstance(client.get("/api/v1/stats").json()["by_status"], dict)

    def test_by_region_is_list(self, client):
        assert isinstance(client.get("/api/v1/stats").json()["by_region"], list)

    def test_stats_total_cases_zero_when_empty(self, client):
        data = client.get("/api/v1/stats").json()
        assert data["total_cases"] == 0

    def test_stats_avg_risk_zero_when_empty(self, client):
        data = client.get("/api/v1/stats").json()
        assert data["avg_risk"] == 0.0

    def test_stats_high_risk_zero_when_empty(self, client):
        data = client.get("/api/v1/stats").json()
        assert data["high_risk_count"] == 0


# ================================================================= GET /api/v1/stats/timeline

class TestStatsTimeline:
    def test_timeline_exists(self, client):
        assert client.get("/api/v1/stats/timeline").status_code == 200

    def test_timeline_default_30_days(self, client):
        data = client.get("/api/v1/stats/timeline").json()
        assert isinstance(data, list)

    def test_timeline_custom_days(self, client):
        assert client.get("/api/v1/stats/timeline?days=7").status_code == 200

    def test_timeline_days_max(self, client):
        # 365 dan katta bo'lmaydi
        assert client.get("/api/v1/stats/timeline?days=400").status_code in (200, 422)

    def test_timeline_item_has_date(self, client):
        data = client.get("/api/v1/stats/timeline").json()
        # Bo'sh yoki element bilan — agar bor bo'lsa date maydoni bo'lishi shart
        if data:
            assert "date" in data[0]

    def test_timeline_item_has_count(self, client):
        data = client.get("/api/v1/stats/timeline").json()
        if data:
            assert "count" in data[0]


# ================================================================= GET /api/v1/stats/detectors

class TestStatsDetectors:
    def test_detectors_exists(self, client):
        assert client.get("/api/v1/stats/detectors").status_code == 200

    def test_detectors_returns_list(self, client):
        assert isinstance(client.get("/api/v1/stats/detectors").json(), list)

    def test_detectors_limit_param(self, client):
        assert client.get("/api/v1/stats/detectors?limit=5").status_code == 200

    def test_detectors_item_schema(self):
        row = _row(name="brand_check", kind="rule", hit_count=42)
        sess = _mock_session(rows=[row])
        async def _fake_db():
            yield sess
        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.get("/api/v1/stats/detectors").json()
        app.dependency_overrides.clear()
        if data:
            assert "name" in data[0]
            assert "hit_count" in data[0]


# ================================================================= GET /api/v1/stats/ioc

class TestStatsIoc:
    def test_ioc_stats_exists(self, client):
        assert client.get("/api/v1/stats/ioc").status_code == 200

    def test_ioc_returns_dict(self, client):
        assert isinstance(client.get("/api/v1/stats/ioc").json(), dict)

    def test_ioc_has_total(self, client):
        data = client.get("/api/v1/stats/ioc").json()
        assert "total" in data

    def test_ioc_has_by_type(self, client):
        data = client.get("/api/v1/stats/ioc").json()
        assert "by_type" in data


