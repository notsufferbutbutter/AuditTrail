"""Integration tests: they call the real HTTP API and show login, logout and protection."""

import pytest
from fastapi.testclient import TestClient

from backend.auth import COOKIE
from backend.config import Settings
from backend.main import create_app

ORIGIN = "https://audittrail.example.com"
EMAIL = "person@example.com"
BEARER = {"Authorization": "Bearer any-token"}


@pytest.fixture
def client():
    app = create_app(Settings(origin=ORIGIN))
    with TestClient(app, base_url=ORIGIN, headers={"origin": ORIGIN}) as client:
        # Token checking has its own tests in test_entra.py, so accept every token here.
        client.app.state.entra.identity = lambda token: EMAIL
        yield client


def login(client):
    return client.post("/api/auth/login", headers=BEARER)


def test_health_check_is_public(client):
    assert client.get("/health").json() == {"status": "OK"}


def test_documents_need_login(client):
    assert client.get("/api/documents").status_code == 401


def test_login_then_documents_then_logout(client):
    response = login(client)
    assert response.status_code == 200
    assert response.json() == {"email": EMAIL}
    assert client.get("/api/auth/session").json() == {"email": EMAIL}
    assert client.get("/api/documents").status_code == 200
    assert client.get("/api/documents").json() == []

    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/session").status_code == 401
    assert client.get("/api/documents").status_code == 401


def test_old_cookie_does_not_work_after_logout(client):
    cookie = login(client).cookies[COOKIE]
    client.post("/api/auth/logout")
    assert client.get("/api/documents", headers={"cookie": f"{COOKIE}={cookie}"}).status_code == 401


def test_cookie_is_http_only_and_secure(client):
    set_cookie = login(client).headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_login_needs_a_token(client):
    assert client.post("/api/auth/login").status_code == 401
    assert client.post("/api/auth/login", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get("/api/documents").status_code == 401


def test_invalid_cookie_is_rejected(client):
    assert client.get("/api/documents", headers={"cookie": f"{COOKIE}=forged"}).status_code == 401


def test_expired_session_is_rejected(client):
    client.app.state.sessions.lifetime_seconds = -1
    login(client)
    assert client.get("/api/documents").status_code == 401


def test_post_from_other_origin_is_rejected(client):
    other = {"origin": "https://attacker.example.com"}
    assert client.post("/api/auth/login", headers={**BEARER, **other}).status_code == 403
    assert client.post("/api/auth/logout", headers=other).status_code == 403


def test_public_config_for_the_browser(client):
    config = client.get("/api/auth/config").json()
    settings = client.app.state.settings
    assert config["clientId"] == settings.frontend_client_id
    assert config["scope"] == settings.api_scope
    assert config["redirectUri"] == ORIGIN + "/"


def test_api_responses_are_not_cached(client):
    assert client.get("/api/documents").headers["cache-control"] == "no-store"
