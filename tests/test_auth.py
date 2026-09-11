"""Autentifikatsiya va foydalanuvchi moduli sinovlari (TZ: FT-43, FT-44).

TDD: avval testlar, keyin implementatsiya.
HT-03: parol hesh sifatida saqlanadi, javobda hech qachon xom parol yo'q.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt

import app.db as db_module
from app.auth.deps import get_current_user
from app.auth.jwt import _ALGORITHM, _SECRET, create_access_token, decode_token
from app.auth.password import hash_password, verify_password
from app.main import app
from app.models import User, UserRole


# ----------------------------------------------------------------- yordamchi

def _make_user(**kw) -> MagicMock:
    """Sinov uchun User mock obyekti (SQLAlchemy instrumentatsiyasini chetlab o'tadi)."""
    defaults = dict(
        id=uuid.uuid4(),
        username="analyst1",
        password_hash=hash_password("secret123"),
        role=UserRole.analyst,
        mfa_enabled=False,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kw)
    u = MagicMock(spec=User)
    for k, v in defaults.items():
        setattr(u, k, v)
    return u


def _db_returning(scalar=None, scalars=None):
    """DB mock: execute().scalar_one_or_none() va .scalars().all() ni sozlash."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = scalar
    mock_result.scalars.return_value.all.return_value = scalars or []
    session = AsyncMock()
    session.execute = AsyncMock(return_value=mock_result)

    # db.add() sinxron — AsyncMock o'rniga oddiy MagicMock
    session.add = MagicMock()

    # db.refresh(obj): server_default maydonlarini to'ldiradi
    async def _refresh(obj):
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        if getattr(obj, "created_at", None) is None:
            obj.created_at = datetime.now(timezone.utc)
        if getattr(obj, "is_active", None) is None:
            obj.is_active = True
        if getattr(obj, "mfa_enabled", None) is None:
            obj.mfa_enabled = False

    session.refresh = AsyncMock(side_effect=_refresh)
    return session


def _empty_db():
    """Hech qanday natija qaytarmaydigan DB mock."""
    async def _gen():
        yield _db_returning()
    return _gen


@pytest.fixture
def client():
    async def _fake_db():
        yield AsyncMock()
    app.dependency_overrides[db_module.get_db] = _fake_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ================================================================= Parol xeshlash

class TestPasswordHash:
    def test_hash_returns_string(self):
        h = hash_password("test123")
        assert isinstance(h, str) and len(h) > 10

    def test_hash_not_plaintext(self):
        assert hash_password("test123") != "test123"

    def test_verify_correct(self):
        h = hash_password("correct")
        assert verify_password("correct", h) is True

    def test_verify_wrong(self):
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_two_hashes_differ(self):
        # bcrypt: har safar turli salt
        assert hash_password("same") != hash_password("same")


# ================================================================= JWT

class TestJwt:
    def test_create_returns_string(self):
        token = create_access_token("user1")
        assert isinstance(token, str) and len(token) > 20

    def test_decode_returns_subject(self):
        token = create_access_token("user1")
        assert decode_token(token) == "user1"

    def test_token_has_sub_claim(self):
        token = create_access_token("bob")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["sub"] == "bob"

    def test_token_has_exp_claim(self):
        token = create_access_token("bob")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert "exp" in payload

    def test_expired_token_raises(self):
        from jose import JWTError
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        token = jwt.encode({"sub": "u", "exp": past}, _SECRET, algorithm=_ALGORITHM)
        with pytest.raises(JWTError):
            decode_token(token)

    def test_invalid_token_raises(self):
        from jose import JWTError
        with pytest.raises(JWTError):
            decode_token("bu.noto'g'ri.token")

    def test_tampered_token_raises(self):
        from jose import JWTError
        token = create_access_token("user") + "tamper"
        with pytest.raises(JWTError):
            decode_token(token)


# ================================================================= Login endpointi

class TestLoginEndpoint:
    def test_login_success_returns_token(self):
        user = _make_user()

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/auth/login",
                          json={"username": "analyst1", "password": "secret123"})
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password_401(self):
        user = _make_user()

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/auth/login",
                          json={"username": "analyst1", "password": "WRONG"})
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_login_unknown_user_401(self):
        async def _fake_db():
            yield _db_returning(scalar=None)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/auth/login",
                          json={"username": "noone", "password": "x"})
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_login_inactive_user_401(self):
        user = _make_user(is_active=False)

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/auth/login",
                          json={"username": "analyst1", "password": "secret123"})
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_login_missing_fields_422(self, client):
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422

    def test_login_token_is_decodable(self):
        user = _make_user()

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            token = c.post("/api/v1/auth/login",
                           json={"username": "analyst1", "password": "secret123"}).json()["access_token"]
        app.dependency_overrides.clear()
        assert decode_token(token) == "analyst1"


# ================================================================= /users/me

class TestUsersMe:
    def _auth_header(self, username="analyst1"):
        return {"Authorization": f"Bearer {create_access_token(username)}"}

    def test_me_no_token_401(self, client):
        assert client.get("/api/v1/users/me").status_code == 401

    def test_me_invalid_token_401(self, client):
        resp = client.get("/api/v1/users/me",
                          headers={"Authorization": "Bearer noto'g'ri"})
        assert resp.status_code == 401

    def test_me_valid_token_200(self):
        user = _make_user()

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/api/v1/users/me", headers=self._auth_header())
        app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_me_returns_username(self):
        user = _make_user(username="analyst1")

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.get("/api/v1/users/me", headers=self._auth_header("analyst1")).json()
        app.dependency_overrides.clear()
        assert data["username"] == "analyst1"

    def test_me_no_password_in_response(self):
        user = _make_user()

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.get("/api/v1/users/me", headers=self._auth_header()).json()
        app.dependency_overrides.clear()
        # HT-03: parol javobda bo'lmasligi shart
        assert "password" not in data
        assert "password_hash" not in data

    def test_me_role_field_present(self):
        user = _make_user(role=UserRole.analyst)

        async def _fake_db():
            yield _db_returning(scalar=user)

        app.dependency_overrides[db_module.get_db] = _fake_db
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.get("/api/v1/users/me", headers=self._auth_header()).json()
        app.dependency_overrides.clear()
        assert data["role"] == "analyst"


# ================================================================= /users (admin)

class TestUsersCreate:
    def _setup(self, current_user):
        """get_current_user va get_db ni override qiladi."""
        app.dependency_overrides[get_current_user] = lambda: current_user

        async def _fake_db():
            yield _db_returning(scalar=None)  # duplicate yo'q

        app.dependency_overrides[db_module.get_db] = _fake_db

    def test_create_success_201(self):
        admin = _make_user(username="admin1", role=UserRole.admin)
        self._setup(admin)
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/users",
                          json={"username": "newanalyst", "password": "pass123"})
        app.dependency_overrides.clear()
        assert resp.status_code == 201

    def test_create_non_admin_403(self):
        analyst = _make_user(username="analyst1", role=UserRole.analyst)
        app.dependency_overrides[get_current_user] = lambda: analyst
        app.dependency_overrides[db_module.get_db] = _empty_db()
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.post("/api/v1/users", json={"username": "newuser", "password": "yyyyyy"})
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    def test_create_no_auth_401(self, client):
        resp = client.post("/api/v1/users", json={"username": "x", "password": "y"})
        assert resp.status_code == 401

    def test_create_response_no_password(self):
        admin = _make_user(username="admin1", role=UserRole.admin)
        self._setup(admin)
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.post("/api/v1/users",
                          json={"username": "new", "password": "pass123"}).json()
        app.dependency_overrides.clear()
        # HT-03
        assert "password" not in data
        assert "password_hash" not in data

    def test_create_missing_password_422(self, client):
        resp = client.post("/api/v1/users", json={"username": "x"})
        assert resp.status_code in (401, 422)


# ================================================================= /users ro'yxati

class TestUsersList:
    def _setup_admin(self, users=None):
        admin = _make_user(username="admin1", role=UserRole.admin)
        app.dependency_overrides[get_current_user] = lambda: admin

        async def _fake_db():
            yield _db_returning(scalars=users or [])

        app.dependency_overrides[db_module.get_db] = _fake_db
        return admin

    def test_list_returns_list(self):
        self._setup_admin(users=[_make_user(username=f"u{i}") for i in range(3)])
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/api/v1/users")
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_non_admin_403(self):
        analyst = _make_user(username="analyst1", role=UserRole.analyst)
        app.dependency_overrides[get_current_user] = lambda: analyst
        app.dependency_overrides[db_module.get_db] = _empty_db()
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/api/v1/users")
        app.dependency_overrides.clear()
        assert resp.status_code == 403

    def test_list_no_auth_401(self, client):
        assert client.get("/api/v1/users").status_code == 401

    def test_list_count_matches(self):
        users = [_make_user(username=f"u{i}") for i in range(5)]
        self._setup_admin(users=users)
        with TestClient(app, raise_server_exceptions=False) as c:
            data = c.get("/api/v1/users").json()
        app.dependency_overrides.clear()
        assert len(data) == 5
