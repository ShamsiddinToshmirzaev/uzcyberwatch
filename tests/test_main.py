"""FastAPI ilova endpoint sinovlari (TZ: FT-46, NFT-11).

TestClient orqali sinxron test — pytest-anyio shart emas.
DB ga bog'liq endpointlar uchun dependency override ishlatiladi.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_db
from app.models import Case, CaseStatus, Detector, DetectorKind, RawEvent, EventType


# ----------------------------------------------------------------- DB mock

def _mock_db_override():
    """Har bir test uchun yangi mock AsyncSession qaytaradi."""
    async def _gen():
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        yield session
    return _gen


# ----------------------------------------------------------------- fixture

@pytest.fixture(autouse=True)
def override_db():
    """Barcha testlar uchun get_db ni mock bilan almashtiriladi."""
    app.dependency_overrides[get_db] = _mock_db_override()
    yield
    app.dependency_overrides.clear()


@pytest.fixture()
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ----------------------------------------------------------------- /health

class TestHealth:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_body(self, client):
        r = client.get("/health")
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_health_not_requires_auth(self, client):
        # Auth bo'lmasa ham ishlashi kerak
        r = client.get("/health")
        assert r.status_code != 401


# ----------------------------------------------------------------- /api/v1/analyse

class TestAnalyse:
    URL = "/api/v1/analyse"

    def test_analyse_url_returns_verdict(self, client):
        r = client.post(self.URL, json={"url": "http://click-uz.tasdiqlash.com"})
        assert r.status_code == 200
        data = r.json()
        assert "risk_score" in data
        assert "confidence" in data
        assert "incident_type" in data
        assert "reasons" in data

    def test_analyse_text_returns_verdict(self, client):
        r = client.post(self.URL, json={"text": "Kartangizni blokdan chiqarish uchun PIN-kodingizni yuboring"})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] >= 0
        assert 0.0 <= data["confidence"] <= 1.0

    def test_analyse_url_and_text(self, client):
        r = client.post(self.URL, json={
            "url": "http://kapitalbnk.uz.login.xyz",
            "text": "Hisobingiz bloklandi",
        })
        assert r.status_code == 200

    def test_analyse_with_domain_age(self, client):
        r = client.post(self.URL, json={
            "url": "http://newsite.uz",
            "domain_age_days": 3,
        })
        assert r.status_code == 200
        data = r.json()
        # Juda yangi domen ogohlantirishi kelishi kerak
        assert data["risk_score"] > 0

    def test_analyse_ml_score_validated(self, client):
        r = client.post(self.URL, json={"url": "http://example.uz", "ml_score": 1.5})
        assert r.status_code == 422

    def test_analyse_ml_score_negative_rejected(self, client):
        r = client.post(self.URL, json={"url": "http://example.uz", "ml_score": -0.1})
        assert r.status_code == 422

    def test_analyse_no_input_rejected(self, client):
        # URL ham, text ham yo'q — 422
        r = client.post(self.URL, json={})
        assert r.status_code == 422

    def test_analyse_empty_string_rejected(self, client):
        r = client.post(self.URL, json={"url": "", "text": ""})
        assert r.status_code == 422

    def test_analyse_official_domain_low_risk(self, client):
        r = client.post(self.URL, json={"url": "https://click.uz"})
        assert r.status_code == 200
        data = r.json()
        # Rasmiy domen flaglanmasligi kerak
        assert data["risk_score"] < 30

    def test_analyse_typosquat_high_risk(self, client):
        r = client.post(self.URL, json={"url": "http://kapitalbnk.uz"})
        assert r.status_code == 200
        data = r.json()
        assert data["risk_score"] > 20

    def test_reasons_have_required_fields(self, client):
        r = client.post(self.URL, json={"url": "http://payme-kirish.net"})
        assert r.status_code == 200
        for reason in r.json()["reasons"]:
            assert "layer" in reason
            assert "code" in reason
            assert "weight" in reason
            assert "detail" in reason

    def test_legal_suggestions_have_requires_review(self, client):
        # HT-05: requires_review=True doim saqlanishi kerak
        r = client.post(self.URL, json={"url": "http://clik.uz/login"})
        assert r.status_code == 200
        for suggestion in r.json()["legal"]:
            assert suggestion["requires_review"] is True

    def test_pii_not_leaked_raw(self, client):
        # HT-03: xom PII javobda bo'lmasligi kerak
        r = client.post(self.URL, json={"text": "Kartangiz: 8600 1234 5678 9012"})
        assert r.status_code == 200
        data = r.json()
        raw = str(data)
        # Karta raqami xom holda javobda bo'lmasligi kerak
        assert "8600123456789012" not in raw
        assert "8600 1234 5678 9012" not in raw

    def test_pii_found_has_hash_and_hint_only(self, client):
        # HT-03: pii_found da faqat hash va hint
        r = client.post(self.URL, json={"text": "+998901234567 ga pul o'tkazing"})
        assert r.status_code == 200
        for pii_item in r.json()["pii_found"]:
            assert "hash" in pii_item
            assert "hint" in pii_item
            # Xom qiymat bo'lmasligi kerak
            assert "raw" not in pii_item
            assert "value" not in pii_item

    def test_analyse_has_payload_flag(self, client):
        r = client.post(self.URL, json={
            "url": "http://malware-site.xyz/download.exe",
            "has_payload": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["incident_type"] == "malware"


# ----------------------------------------------------------------- /api/v1/cases

class TestCases:
    BASE = "/api/v1/cases"

    def _make_case(self, **kwargs) -> MagicMock:
        defaults = dict(
            id=uuid.uuid4(),
            title="Test ishi",
            status=CaseStatus.new,
            total_risk=50,
            opened_at=datetime.now(timezone.utc),
            closed_at=None,
            region="Toshkent",
            assignee_id=None,
            article_code=None,
            article_conf=None,
        )
        defaults.update(kwargs)
        c = MagicMock()
        for k, v in defaults.items():
            setattr(c, k, v)
        return c

    def _setup_list(self, session_mock, cases: list):
        result = MagicMock()
        result.scalars.return_value.all.return_value = cases
        session_mock.execute.return_value = result

    def _setup_get(self, session_mock, case):
        result = MagicMock()
        result.scalar_one_or_none.return_value = case
        session_mock.execute.return_value = result

    def test_list_cases_returns_200(self, client, override_db):
        async def _db():
            s = AsyncMock()
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            s.execute.return_value = result
            yield s
        app.dependency_overrides[get_db] = _db
        r = client.get(self.BASE)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_cases_pagination_params(self, client, override_db):
        async def _db():
            s = AsyncMock()
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            s.execute.return_value = result
            yield s
        app.dependency_overrides[get_db] = _db
        r = client.get(self.BASE + "?page=1&size=10")
        assert r.status_code == 200

    def test_list_cases_invalid_page_rejected(self, client):
        r = client.get(self.BASE + "?page=0")
        assert r.status_code == 422

    def test_list_cases_size_too_large_rejected(self, client):
        r = client.get(self.BASE + "?size=200")
        assert r.status_code == 422

    def test_create_case_success(self, client, override_db):
        new_case = self._make_case()

        async def _db():
            s = AsyncMock()
            s.add = MagicMock()
            s.flush = AsyncMock()
            s.commit = AsyncMock()
            async def _refresh(obj):
                obj.id = new_case.id
                obj.status = CaseStatus.new
                obj.total_risk = 0
                obj.opened_at = new_case.opened_at
                obj.closed_at = None
                obj.article_code = None
                obj.article_conf = None
                obj.assignee_id = None
            s.refresh = _refresh
            yield s
        app.dependency_overrides[get_db] = _db

        r = client.post(self.BASE, json={"title": "Yangi ish", "region": "Samarqand"})
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "Yangi ish"
        assert data["status"] == "new"

    def test_create_case_title_required(self, client):
        r = client.post(self.BASE, json={"region": "Toshkent"})
        assert r.status_code == 422

    def test_get_case_not_found(self, client, override_db):
        async def _db():
            s = AsyncMock()
            result = MagicMock()
            result.scalar_one_or_none.return_value = None
            s.execute.return_value = result
            yield s
        app.dependency_overrides[get_db] = _db
        r = client.get(f"{self.BASE}/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_get_case_found(self, client, override_db):
        case = self._make_case(title="Topilgan ish")

        async def _db():
            s = AsyncMock()
            result = MagicMock()
            result.scalar_one_or_none.return_value = case
            s.execute.return_value = result
            yield s
        app.dependency_overrides[get_db] = _db
        r = client.get(f"{self.BASE}/{case.id}")
        assert r.status_code == 200
        assert r.json()["title"] == "Topilgan ish"

    def test_patch_case_status(self, client, override_db):
        case = self._make_case(status=CaseStatus.new)

        async def _db():
            s = AsyncMock()
            result = MagicMock()
            result.scalar_one_or_none.return_value = case
            s.execute.return_value = result
            s.commit = AsyncMock()
            yield s
        app.dependency_overrides[get_db] = _db
        r = client.patch(f"{self.BASE}/{case.id}", json={"status": "triage"})
        assert r.status_code == 200
        assert r.json()["status"] == "triage"

    def test_patch_case_invalid_status(self, client):
        r = client.patch(f"{self.BASE}/{uuid.uuid4()}", json={"status": "noto'g'ri"})
        assert r.status_code == 422


# ----------------------------------------------------------------- OpenAPI

class TestOpenAPI:
    def test_openapi_schema_accessible(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200

    def test_docs_accessible(self, client):
        r = client.get("/docs")
        assert r.status_code == 200

    def test_api_title_in_schema(self, client):
        r = client.get("/openapi.json")
        assert "UzCyberWatch" in r.json()["info"]["title"]
