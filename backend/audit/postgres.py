"""PostgreSQL implementation of the AuditRepository contract.

Each call opens a short-lived connection with the app's restricted database login
(role audittrail_app: no UPDATE/DELETE on audit_events). All SQL is parameterised.
"""
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from backend.audit.repository import ApiKeyScope, EventConflict, FailedLoginStats
from backend.audit.schemas import (
    AlertRecord, AlertStatus, AlertWrite, Environment, EventRecord, EventWrite, Outcome,
)
from backend.db import connect
from backend.repositories import ApiKeyRepository

_SOURCE_FIELDS = ("service_id", "action", "outcome", "actor", "targets", "occurred_at", "metadata")


class PostgresAuditRepository:
    def __init__(self, connect_fn: Callable[[], psycopg.Connection] = connect):
        self._connect = connect_fn

    def _rows(self, sql: str, params) -> list[dict]:
        with self._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchall() if cur.description else []

    def verify_api_key(self, raw_key: str) -> ApiKeyScope | None:
        with self._connect() as conn:
            scope = ApiKeyRepository(conn).verify(raw_key)
        if scope is None:
            return None
        return ApiKeyScope(application_id=scope.application_id,
                           environment=scope.environment, key_id=scope.key_id)

    def find_service_id(self, application_id: UUID, source_id: str) -> UUID | None:
        rows = self._rows("SELECT id FROM services WHERE application_id = %s AND source_id = %s",
                          (application_id, source_id))
        return rows[0]["id"] if rows else None

    def insert_or_get_event(self, event: EventWrite) -> tuple[EventRecord, bool]:
        data = event.model_dump()
        rows = self._rows(
            """INSERT INTO audit_events (event_id, application_id, environment, service_id, action,
                                         outcome, actor, targets, occurred_at, received_at, metadata)
               VALUES (%(event_id)s, %(application_id)s, %(environment)s, %(service_id)s, %(action)s,
                       %(outcome)s, %(actor)s, %(targets)s, %(occurred_at)s, %(received_at)s, %(metadata)s)
               ON CONFLICT (application_id, environment, event_id) DO NOTHING
               RETURNING *""",
            {**data, "actor": Jsonb(data["actor"]), "targets": Jsonb(data["targets"]),
             "metadata": Jsonb(data["metadata"]) if data["metadata"] is not None else None})
        if rows:
            return EventRecord(**rows[0]), True

        existing = self._rows(
            "SELECT * FROM audit_events WHERE application_id = %s AND environment = %s AND event_id = %s",
            (event.application_id, event.environment, event.event_id))
        stored = EventRecord(**existing[0])
        if any(getattr(stored, f) != getattr(event, f) for f in _SOURCE_FIELDS):
            raise EventConflict(event.event_id)
        return stored, False

    def get_event(self, event_id: UUID) -> EventRecord | None:
        rows = self._rows("SELECT * FROM audit_events WHERE id = %s", (event_id,))
        return EventRecord(**rows[0]) if rows else None

    def list_events(self, *, application_id: UUID | None, environment: Environment | None,
                    service_id: UUID | None, action: str | None, outcome: Outcome | None,
                    limit: int, offset: int) -> list[EventRecord]:
        rows = self._rows(
            """SELECT * FROM audit_events
               WHERE (%(app)s::uuid IS NULL OR application_id = %(app)s)
                 AND (%(env)s::text IS NULL OR environment = %(env)s)
                 AND (%(svc)s::uuid IS NULL OR service_id = %(svc)s)
                 AND (%(action)s::text IS NULL OR action = %(action)s)
                 AND (%(outcome)s::text IS NULL OR outcome = %(outcome)s)
               ORDER BY received_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s""",
            {"app": application_id, "env": environment, "svc": service_id, "action": action,
             "outcome": outcome, "limit": limit, "offset": offset})
        return [EventRecord(**r) for r in rows]

    def count_failed_logins(self, *, application_id: UUID, environment: Environment, service_id: UUID,
                            actor_id: str, since: datetime, until: datetime) -> FailedLoginStats | None:
        rows = self._rows(
            """SELECT count(*) AS count, min(received_at) AS first, max(received_at) AS last
               FROM audit_events
               WHERE application_id = %s AND environment = %s AND service_id = %s
                 AND action = 'user.login' AND outcome = 'failure'
                 AND actor ->> 'type' = 'user' AND actor ->> 'id' = %s
                 AND received_at BETWEEN %s AND %s""",
            (application_id, environment, service_id, actor_id, since, until))
        row = rows[0]
        if not row["count"]:
            return None
        return FailedLoginStats(count=row["count"], first_received_at=row["first"],
                                last_received_at=row["last"])

    def upsert_alert(self, alert: AlertWrite) -> AlertRecord:
        rows = self._rows(
            """INSERT INTO alerts (application_id, environment, service_id, rule_code, actor_id, severity,
                                   status, title, description, failure_count, window_start, window_end,
                                   first_seen_at, last_seen_at)
               VALUES (%(application_id)s, %(environment)s, %(service_id)s, %(rule_code)s, %(actor_id)s,
                       %(severity)s, %(status)s, %(title)s, %(description)s, %(failure_count)s,
                       %(window_start)s, %(window_end)s, %(first_seen_at)s, %(last_seen_at)s)
               ON CONFLICT (application_id, environment, service_id, rule_code, actor_id)
                   WHERE status <> 'resolved'
               DO UPDATE SET failure_count = EXCLUDED.failure_count,
                             severity      = EXCLUDED.severity,
                             description   = EXCLUDED.description,
                             window_start  = EXCLUDED.window_start,
                             window_end    = EXCLUDED.window_end,
                             last_seen_at  = GREATEST(alerts.last_seen_at, EXCLUDED.last_seen_at),
                             updated_at    = now()
               RETURNING *""",
            alert.model_dump())
        return AlertRecord(**rows[0])

    def get_alert(self, alert_id: UUID) -> AlertRecord | None:
        rows = self._rows("SELECT * FROM alerts WHERE id = %s", (alert_id,))
        return AlertRecord(**rows[0]) if rows else None

    def list_alerts(self, *, application_id: UUID | None, environment: Environment | None,
                    status: AlertStatus | None, limit: int, offset: int) -> list[AlertRecord]:
        rows = self._rows(
            """SELECT * FROM alerts
               WHERE (%(app)s::uuid IS NULL OR application_id = %(app)s)
                 AND (%(env)s::text IS NULL OR environment = %(env)s)
                 AND (%(status)s::text IS NULL OR status = %(status)s)
               ORDER BY created_at DESC, id DESC LIMIT %(limit)s OFFSET %(offset)s""",
            {"app": application_id, "env": environment, "status": status,
             "limit": limit, "offset": offset})
        return [AlertRecord(**r) for r in rows]
