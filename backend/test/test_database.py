"""Database tests against a real PostgreSQL.

Needs TEST_DATABASE_URL pointing at a server where that login may create databases and roles,
e.g. postgresql://postgres:postgres@localhost:5432/postgres (local or CI service container).
Skipped when it is not set. Never point it at the production server.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest

psycopg = pytest.importorskip("psycopg")
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from backend.migrate import migrate  # noqa: E402
from backend.repositories import AlertRepository, ApiKeyRepository, EventRepository  # noqa: E402

ADMIN_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="TEST_DATABASE_URL not set")
NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def database():
    name = "audittrail_test_" + secrets.token_hex(4)
    app_password = secrets.token_urlsafe(16)
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    owner_info = make_conninfo(ADMIN_URL, dbname=name)
    with psycopg.connect(owner_info) as owner:
        migrate(owner)
        owner.execute(f"DROP ROLE IF EXISTS app_test")
        owner.execute(f"CREATE ROLE app_test LOGIN PASSWORD '{app_password}' IN ROLE audittrail_app")
        owner.commit()
    params = conninfo_to_dict(owner_info) | {"user": "app_test", "password": app_password}
    yield owner_info, make_conninfo(**params)
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
        admin.execute("DROP ROLE IF EXISTS app_test")


@pytest.fixture
def owner(database):
    with psycopg.connect(database[0], autocommit=True) as conn:
        yield conn


@pytest.fixture
def app_conn(database):
    """Connection with the app's restricted role, as in production."""
    with psycopg.connect(database[1], autocommit=True) as conn:
        yield conn


@pytest.fixture
def app_with_service(owner):
    app_id = owner.execute("INSERT INTO applications (name) VALUES ('shop') RETURNING id").fetchone()[0]
    service_id = owner.execute(
        "INSERT INTO services (application_id, source_id, name) VALUES (%s, 'auth-service', 'Auth') RETURNING id",
        (app_id,)).fetchone()[0]
    return app_id, service_id


def event(event_id="evt-001", outcome="failure"):
    return {"event_id": event_id, "source_id": "auth-service", "action": "user.login",
            "outcome": outcome, "actor": {"type": "user", "id": "user-123"},
            "targets": [], "occurred_at": NOW, "metadata": {"ip": "203.0.113.5"}}


def test_migrations_run_once(owner):
    assert migrate(owner) == []


def test_api_key_is_stored_only_as_hash(owner, app_conn, app_with_service):
    key = ApiKeyRepository(app_conn).create(app_with_service[0], "dev")
    stored = owner.execute("SELECT key_hash FROM api_keys WHERE key_id = %s", (key.key_id,)).fetchone()[0]
    secret = key.plaintext.split(".", 1)[1]
    assert secret not in stored and len(stored) == 64


def test_valid_key_returns_scope(app_conn, app_with_service):
    keys = ApiKeyRepository(app_conn)
    key = keys.create(app_with_service[0], "prod")
    scope = keys.verify(key.plaintext)
    assert scope.application_id == app_with_service[0] and scope.environment == "prod"


@pytest.mark.parametrize("presented", [None, "", "garbage", "at_unknown.xxxxxxxxxxxxxxxxxxxxxxxx"])
def test_invalid_keys_rejected(app_conn, presented):
    assert ApiKeyRepository(app_conn).verify(presented) is None


def test_wrong_secret_revoked_and_expired_keys_rejected(app_conn, app_with_service):
    keys = ApiKeyRepository(app_conn)
    key = keys.create(app_with_service[0], "dev")
    assert keys.verify(key.key_id + "." + "x" * 43) is None
    assert keys.revoke(key.key_id) and keys.verify(key.plaintext) is None
    expired = keys.create(app_with_service[0], "dev", expires_at=NOW - timedelta(minutes=1))
    assert keys.verify(expired.plaintext) is None


def test_event_insert_and_duplicate_is_idempotent(app_conn, app_with_service):
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    scope = keys.verify(keys.create(app_with_service[0], "dev").plaintext)
    first, created = events.insert(scope, event("evt-dup"))
    again, created_again = events.insert(scope, event("evt-dup"))
    assert created and not created_again and first["id"] == again["id"]
    assert first["service_id"] == app_with_service[1]


def test_same_event_id_in_other_environment_is_not_a_duplicate(app_conn, app_with_service):
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    dev = keys.verify(keys.create(app_with_service[0], "dev").plaintext)
    prod = keys.verify(keys.create(app_with_service[0], "prod").plaintext)
    assert events.insert(dev, event("evt-env"))[1] and events.insert(prod, event("evt-env"))[1]


def test_events_are_scoped_to_their_application(owner, app_conn, app_with_service):
    other_app = owner.execute("INSERT INTO applications (name) VALUES ('other') RETURNING id").fetchone()[0]
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    scope = keys.verify(keys.create(app_with_service[0], "stg").plaintext)
    stored, _ = events.insert(scope, event("evt-scope"))
    assert events.get(app_with_service[0], "stg", id=stored["id"]) is not None
    assert events.get(other_app, "stg", id=stored["id"]) is None
    assert events.list(other_app, "stg") == []


def test_unknown_service_rejected(app_conn, app_with_service):
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    scope = keys.verify(keys.create(app_with_service[0], "dev").plaintext)
    with pytest.raises(LookupError):
        events.insert(scope, {**event("evt-x"), "source_id": "not-registered"})


def test_app_role_cannot_update_or_delete_events(app_conn, app_with_service):
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    scope = keys.verify(keys.create(app_with_service[0], "dev").plaintext)
    events.insert(scope, event("evt-locked"))
    for sql in ("UPDATE audit_events SET action = 'x'", "DELETE FROM audit_events",
                "TRUNCATE audit_events"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app_conn.execute(sql)


def test_even_owner_is_blocked_by_append_only_trigger(owner, app_conn, app_with_service):
    keys, events = ApiKeyRepository(app_conn), EventRepository(app_conn)
    scope = keys.verify(keys.create(app_with_service[0], "dev").plaintext)
    events.insert(scope, event("evt-trigger"))
    for sql in ("UPDATE audit_events SET action = 'x'", "DELETE FROM audit_events"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            owner.execute(sql)


def test_alert_upsert_updates_open_alert(app_conn, app_with_service):
    app_id, service_id = app_with_service
    alerts = AlertRepository(app_conn)
    base = {"application_id": app_id, "environment": "dev", "service_id": service_id,
            "rule_code": "repeated_login_failures", "actor_id": "user-123", "severity": "medium",
            "title": "Repeated failed logins", "failure_count": 5,
            "window_start": NOW - timedelta(minutes=5), "window_end": NOW,
            "first_seen_at": NOW - timedelta(minutes=4), "last_seen_at": NOW}
    first = alerts.upsert(base)
    second = alerts.upsert({**base, "failure_count": 8, "severity": "high"})
    assert first["id"] == second["id"] and second["failure_count"] == 8
    assert alerts.get(app_id, "dev", first["id"])["severity"] == "high"
    assert len(alerts.list(app_id, "dev")) == 1
