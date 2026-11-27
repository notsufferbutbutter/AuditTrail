"""Data access for AuditTrail. All SQL is parameterised (no string formatting with user input).

Every read is scoped to (application_id, environment), so one application can never see
another application's events or alerts. There is deliberately no update/delete for events.
"""
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

ENVIRONMENTS = ("dev", "stg", "prod")
MAX_PAGE = 100
# Same work for unknown key IDs as for known ones, so response time does not reveal valid IDs.
_DUMMY_HASH = "0" * 64


@dataclass(frozen=True)
class KeyScope:
    """What a verified API key is allowed to do: write events for one app in one environment."""
    application_id: UUID
    environment: str
    key_id: str


@dataclass(frozen=True)
class NewApiKey:
    key_id: str
    plaintext: str  # shown to the user exactly once, never stored


def _hash(secret: str) -> str:
    # The secret is 256 random bits, so a fast hash is enough (no password stretching needed).
    return hashlib.sha256(secret.encode()).hexdigest()


def _split_key(presented: str) -> tuple[str, str] | None:
    key_id, sep, secret = presented.partition(".")
    if not sep or not key_id.startswith("at_") or len(key_id) > 50 or not 20 <= len(secret) <= 100:
        return None
    return key_id, secret


class ApiKeyRepository:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def create(self, application_id: UUID, environment: str, expires_at: datetime | None = None) -> NewApiKey:
        if environment not in ENVIRONMENTS:
            raise ValueError("environment must be dev, stg or prod")
        key_id = "at_" + secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        self.conn.execute(
            """INSERT INTO api_keys (application_id, environment, key_id, key_hash, expires_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (application_id, environment, key_id, _hash(secret), expires_at))
        return NewApiKey(key_id=key_id, plaintext=f"{key_id}.{secret}")

    def verify(self, presented: str | None) -> KeyScope | None:
        """Return the key's scope, or None for unknown, wrong, revoked or expired keys."""
        parts = _split_key(presented or "")
        key_id, secret = parts if parts else ("", "")
        row = None
        if parts:
            row = self.conn.execute(
                """SELECT application_id, environment, key_hash,
                          status = 'active' AND (expires_at IS NULL OR expires_at > now()) AS usable
                   FROM api_keys WHERE key_id = %s""", (key_id,)).fetchone()
        stored = row[2] if row else _DUMMY_HASH
        matches = hmac.compare_digest(_hash(secret), stored)
        if row and matches and row[3]:
            return KeyScope(application_id=row[0], environment=row[1], key_id=key_id)
        return None

    def revoke(self, key_id: str) -> bool:
        cur = self.conn.execute(
            """UPDATE api_keys SET status = 'revoked', revoked_at = now()
               WHERE key_id = %s AND status = 'active'""", (key_id,))
        return cur.rowcount == 1


class EventRepository:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def insert(self, scope: KeyScope, event: dict[str, Any]) -> tuple[dict, bool]:
        """Store an event for the key's application/environment.

        Returns (event, created). A retry with the same event_id returns the stored event
        with created=False instead of storing it twice. Application and environment come
        from the key, never from the request body.
        """
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """INSERT INTO audit_events (event_id, application_id, environment, service_id,
                                             action, outcome, actor, targets, occurred_at, metadata)
                   SELECT %(event_id)s, %(app)s, %(env)s, s.id, %(action)s, %(outcome)s,
                          %(actor)s, %(targets)s, %(occurred_at)s, %(metadata)s
                   FROM services s WHERE s.application_id = %(app)s AND s.source_id = %(source_id)s
                   ON CONFLICT (application_id, environment, event_id) DO NOTHING
                   RETURNING *""",
                {"event_id": event["event_id"], "app": scope.application_id, "env": scope.environment,
                 "source_id": event["source_id"], "action": event["action"], "outcome": event["outcome"],
                 "actor": Jsonb(event["actor"]), "targets": Jsonb(event.get("targets", [])),
                 "occurred_at": event["occurred_at"],
                 "metadata": Jsonb(event["metadata"]) if event.get("metadata") is not None else None})
            row = cur.fetchone()
        if row:
            return row, True
        existing = self.get(scope.application_id, scope.environment, event_id=event["event_id"])
        if existing is None:
            raise LookupError("Unknown service for this application")
        return existing, False

    def get(self, application_id: UUID, environment: str, *, id: UUID | None = None,
            event_id: str | None = None) -> dict | None:
        column, value = ("id", id) if id is not None else ("event_id", event_id)
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                f"""SELECT * FROM audit_events
                    WHERE application_id = %s AND environment = %s AND {column} = %s""",
                (application_id, environment, value))
            return cur.fetchone()

    def list(self, application_id: UUID, environment: str, *, limit: int = 50,
             received_before: datetime | None = None) -> list[dict]:
        limit = max(1, min(limit, MAX_PAGE))
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT * FROM audit_events
                   WHERE application_id = %s AND environment = %s
                     AND (%s::timestamptz IS NULL OR received_at < %s)
                   ORDER BY received_at DESC, id DESC LIMIT %s""",
                (application_id, environment, received_before, received_before, limit))
            return cur.fetchall()


class AlertRepository:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def upsert(self, alert: dict[str, Any]) -> dict:
        """Create an alert, or update the open one for the same app/env/service/rule/actor."""
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """INSERT INTO alerts (application_id, environment, service_id, rule_code, actor_id,
                                       severity, title, description, failure_count,
                                       window_start, window_end, first_seen_at, last_seen_at)
                   VALUES (%(application_id)s, %(environment)s, %(service_id)s, %(rule_code)s,
                           %(actor_id)s, %(severity)s, %(title)s, %(description)s, %(failure_count)s,
                           %(window_start)s, %(window_end)s, %(first_seen_at)s, %(last_seen_at)s)
                   ON CONFLICT (application_id, environment, service_id, rule_code, actor_id)
                       WHERE status <> 'resolved'
                   DO UPDATE SET failure_count = EXCLUDED.failure_count,
                                 severity      = EXCLUDED.severity,
                                 window_end    = EXCLUDED.window_end,
                                 last_seen_at  = GREATEST(alerts.last_seen_at, EXCLUDED.last_seen_at),
                                 updated_at    = now()
                   RETURNING *""",
                {"description": None, **alert})
            return cur.fetchone()

    def get(self, application_id: UUID, environment: str, alert_id: UUID) -> dict | None:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""SELECT * FROM alerts
                           WHERE application_id = %s AND environment = %s AND id = %s""",
                        (application_id, environment, alert_id))
            return cur.fetchone()

    def list(self, application_id: UUID, environment: str, *, limit: int = 50) -> list[dict]:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""SELECT * FROM alerts WHERE application_id = %s AND environment = %s
                           ORDER BY created_at DESC LIMIT %s""",
                        (application_id, environment, max(1, min(limit, MAX_PAGE))))
            return cur.fetchall()
