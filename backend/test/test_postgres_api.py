"""End-to-end: the real audit API on top of the real PostgreSQL adapter.

Uses the database fixtures from test_database.py (needs TEST_DATABASE_URL, otherwise skipped).
"""
import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.audit.postgres import PostgresAuditRepository
from backend.auth.entra import Identity
from backend.config import Settings
from backend.main import create_app
from backend.repositories import ApiKeyRepository
from backend.test.test_database import ADMIN_URL, database  # noqa: F401  (shared fixture)

pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="TEST_DATABASE_URL not set")
ORIGIN = "https://audittrail.example.com"


@pytest.fixture
def setup(database):  # noqa: F811
    owner_info, app_info = database
    with psycopg.connect(owner_info, autocommit=True) as owner:
        app_id = owner.execute("INSERT INTO applications (name) VALUES ('api-test') RETURNING id").fetchone()[0]
        owner.execute("INSERT INTO services (application_id, source_id, name) VALUES (%s, 'auth-service', 'Auth')",
                      (app_id,))
    with psycopg.connect(app_info, autocommit=True) as conn:
        key = ApiKeyRepository(conn).create(app_id, "dev").plaintext
    app = create_app(Settings(origin=ORIGIN))
    with TestClient(app, base_url=ORIGIN, headers={"origin": ORIGIN}) as client:
        client.app.state.entra.identity = lambda *_: Identity("person@example.com", frozenset({"Admin"}))
        client.app.state.audit_repository = PostgresAuditRepository(lambda: psycopg.connect(app_info))
        yield client, key, app_id


def payload(event_id, **extra):
    return {"event_id": event_id, "source_id": "auth-service", "action": "user.login",
            "outcome": "failure", "actor": {"type": "user", "id": "user-9"}, "targets": [],
            "occurred_at": "2026-11-27T00:00:00Z", "metadata": {"ip": "192.0.2.10"}, **extra}


def test_full_flow_against_postgres(setup):
    client, key, app_id = setup
    ingest = lambda p: client.post("/v1/ingest", headers={"X-API-Key": key}, json=p)

    assert client.post("/v1/ingest", headers={"X-API-Key": "at_x.wrongwrongwrongwrongwrong"},
                       json=payload("e0")).status_code == 401
    first = ingest(payload("e1"))
    assert first.status_code == 201 and first.json()["application_id"] == str(app_id)
    assert ingest(payload("e1")).status_code == 200                     # idempotent retry
    assert ingest(payload("e1", action="user.logout")).status_code == 409  # same id, new content
    assert ingest(payload("e2", source_id="unknown")).status_code == 422

    for i in range(2, 6):
        assert ingest(payload(f"e{i}")).status_code == 201             # 5 failures in total

    assert client.get("/v1/events").status_code == 401                 # dashboard needs login
    assert client.post("/api/auth/login", headers={"Authorization": "Bearer t"}).status_code == 200
    events = client.get("/v1/events", params={"application_id": str(app_id)}).json()
    assert len(events) == 5
    assert client.get(f"/v1/events/{first.json()['id']}").json()["event_id"] == "e1"

    alerts = client.get("/v1/alerts", params={"application_id": str(app_id)}).json()
    assert len(alerts) == 1 and alerts[0]["failure_count"] == 5
    assert client.get(f"/v1/alerts/{alerts[0]['id']}").status_code == 200
