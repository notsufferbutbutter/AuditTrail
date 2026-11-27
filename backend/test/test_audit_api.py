from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.audit.repository import (
    ApiKeyScope,
    EventConflict,
    FailedLoginStats,
)
from backend.audit.schemas import (
    AlertRecord,
    AlertWrite,
    EventRecord,
    EventWrite,
)
from backend.auth.entra import Identity
from backend.config import Settings
from backend.main import create_app

ORIGIN = "https://audittrail.example.com"
EMAIL = "person@example.com"
ADMIN = Identity(EMAIL, frozenset({"Admin"}))
APPLICATION_ID = UUID("f0b7bcaa-37fb-4b3b-b24d-3e55596cf746")
SERVICE_ID = UUID("77708f66-140e-4cb0-a953-cd62729b9038")
OTHER_SERVICE_ID = UUID("1c4d2e0c-3158-46ae-aa81-7c62244b5b69")
API_KEY = "test-source-secret"


class FakeAuditRepository:
    def __init__(self) -> None:
        self.events: dict[UUID, EventRecord] = {}
        self.alerts: dict[UUID, AlertRecord] = {}
        self.api_key_scope = ApiKeyScope(
            application_id=APPLICATION_ID,
            environment="dev",
            key_id="test-key",
        )

    def verify_api_key(self, raw_key: str) -> ApiKeyScope | None:
        return self.api_key_scope if raw_key == API_KEY else None

    def find_service_id(self, application_id: UUID, source_id: str) -> UUID | None:
        if application_id == APPLICATION_ID:
            if source_id == "auth-service":
                return SERVICE_ID
            if source_id == "other-auth-service":
                return OTHER_SERVICE_ID
        return None

    def insert_or_get_event(self, event: EventWrite) -> tuple[EventRecord, bool]:
        existing = next(
            (
                item
                for item in self.events.values()
                if item.application_id == event.application_id
                and item.environment == event.environment
                and item.event_id == event.event_id
            ),
            None,
        )
        if existing is not None:
            if existing.model_dump(exclude={"id", "received_at"}) != event.model_dump(
                exclude={"received_at"}
            ):
                raise EventConflict
            return existing, False

        record = EventRecord(id=uuid4(), **event.model_dump())
        self.events[record.id] = record
        return record, True

    def get_event(self, event_id: UUID) -> EventRecord | None:
        return self.events.get(event_id)

    def list_events(
        self,
        *,
        application_id: UUID | None,
        environment: str | None,
        service_id: UUID | None,
        action: str | None,
        outcome: str | None,
        limit: int,
        offset: int,
    ) -> list[EventRecord]:
        results = list(self.events.values())
        if application_id is not None:
            results = [item for item in results if item.application_id == application_id]
        if environment is not None:
            results = [item for item in results if item.environment == environment]
        if service_id is not None:
            results = [item for item in results if item.service_id == service_id]
        if action is not None:
            results = [item for item in results if item.action == action]
        if outcome is not None:
            results = [item for item in results if item.outcome == outcome]
        results.sort(key=lambda item: item.received_at, reverse=True)
        return results[offset : offset + limit]

    def count_failed_logins(
        self,
        *,
        application_id: UUID,
        environment: str,
        service_id: UUID,
        actor_id: str,
        since: datetime,
        until: datetime,
    ) -> FailedLoginStats | None:
        matching = [
            item
            for item in self.events.values()
            if item.application_id == application_id
            and item.environment == environment
            and item.service_id == service_id
            and item.action == "user.login"
            and item.outcome == "failure"
            and item.actor["type"] == "user"
            and item.actor["id"] == actor_id
            and since <= item.received_at <= until
        ]
        if not matching:
            return None
        times = [item.received_at for item in matching]
        return FailedLoginStats(
            count=len(matching),
            first_received_at=min(times),
            last_received_at=max(times),
        )

    def upsert_alert(self, alert: AlertWrite) -> AlertRecord:
        existing = next(
            (
                item
                for item in self.alerts.values()
                if item.application_id == alert.application_id
                and item.environment == alert.environment
                and item.service_id == alert.service_id
                and item.rule_code == alert.rule_code
                and item.actor_id == alert.actor_id
                and item.status in {"open", "acknowledged"}
            ),
            None,
        )
        now = datetime.now(timezone.utc)
        if existing is not None:
            updated = AlertRecord(
                id=existing.id,
                created_at=existing.created_at,
                updated_at=now,
                **alert.model_dump(),
            )
            self.alerts[existing.id] = updated
            return updated

        record = AlertRecord(
            id=uuid4(),
            created_at=now,
            updated_at=now,
            **alert.model_dump(),
        )
        self.alerts[record.id] = record
        return record

    def get_alert(self, alert_id: UUID) -> AlertRecord | None:
        return self.alerts.get(alert_id)

    def list_alerts(
        self,
        *,
        application_id: UUID | None,
        environment: str | None,
        status: str | None,
        limit: int,
        offset: int,
    ) -> list[AlertRecord]:
        results = list(self.alerts.values())
        if application_id is not None:
            results = [item for item in results if item.application_id == application_id]
        if environment is not None:
            results = [item for item in results if item.environment == environment]
        if status is not None:
            results = [item for item in results if item.status == status]
        results.sort(key=lambda item: item.created_at, reverse=True)
        return results[offset : offset + limit]


@pytest.fixture
def client():
    app = create_app(Settings(origin=ORIGIN))
    with TestClient(app, base_url=ORIGIN, headers={"origin": ORIGIN}) as test_client:
        test_client.app.state.entra.identity = lambda *_: ADMIN
        test_client.app.state.audit_repository = FakeAuditRepository()
        yield test_client


def login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200


def event_payload(event_id: str, **overrides) -> dict:
    payload = {
        "event_id": event_id,
        "source_id": "auth-service",
        "action": "user.login",
        "outcome": "failure",
        "actor": {"type": "user", "id": "user-123"},
        "targets": [],
        "occurred_at": "2026-11-27T00:00:00Z",
        "metadata": {"ip": "192.0.2.10"},
    }
    payload.update(overrides)
    return payload


def ingest(client: TestClient, payload: dict):
    return client.post(
        "/v1/ingest",
        headers={"X-API-Key": API_KEY},
        json=payload,
    )


def test_ingest_requires_valid_source_api_key(client: TestClient):
    assert client.post("/v1/ingest", json=event_payload("evt-1")).status_code == 401
    response = client.post(
        "/v1/ingest",
        headers={"X-API-Key": "invalid"},
        json=event_payload("evt-1"),
    )
    assert response.status_code == 401


def test_ingest_derives_scope_and_received_at_on_server(client: TestClient):
    response = ingest(client, event_payload("evt-1"))

    assert response.status_code == 201
    record = response.json()
    assert record["application_id"] == str(APPLICATION_ID)
    assert record["environment"] == "dev"
    assert record["service_id"] == str(SERVICE_ID)
    assert datetime.fromisoformat(record["received_at"].replace("Z", "+00:00")).tzinfo


@pytest.mark.parametrize(
    "overrides",
    [
        {"application_id": str(uuid4())},
        {"environment": "prod"},
        {"received_at": "2026-11-27T00:00:00Z"},
        {"outcome": "unknown"},
        {"occurred_at": "2026-11-27T00:00:00"},
    ],
)
def test_ingest_rejects_spoofed_scope_and_invalid_fields(
    client: TestClient,
    overrides: dict,
):
    assert ingest(client, event_payload("evt-invalid", **overrides)).status_code == 422


def test_ingest_rejects_unknown_service(client: TestClient):
    response = ingest(
        client,
        event_payload("evt-unknown", source_id="unregistered-service"),
    )
    assert response.status_code == 422


def test_event_idempotency_and_conflict(client: TestClient):
    first = ingest(client, event_payload("evt-repeat"))
    retry = ingest(client, event_payload("evt-repeat"))
    conflict = ingest(
        client,
        event_payload("evt-repeat", metadata={"changed": True}),
    )

    assert first.status_code == 201
    assert retry.status_code == 200
    assert retry.json()["id"] == first.json()["id"]
    assert conflict.status_code == 409
    assert len(client.app.state.audit_repository.events) == 1


def test_fifth_failed_login_creates_one_persistent_alert(client: TestClient):
    responses = []
    for index in range(1, 5):
        responses.append(ingest(client, event_payload(f"evt-{index}")))
        assert client.app.state.audit_repository.alerts == {}
    responses.append(ingest(client, event_payload("evt-5")))
    retry = ingest(client, event_payload("evt-5"))

    assert all(response.status_code == 201 for response in responses)
    assert retry.status_code == 200
    repository = client.app.state.audit_repository
    assert len(repository.alerts) == 1
    alert = next(iter(repository.alerts.values()))
    assert alert.failure_count == 5
    assert alert.actor_id == "user-123"


def test_rule_does_not_count_other_users_or_non_login_failures(client: TestClient):
    payloads = [
        event_payload(f"evt-user-{index}", actor={"type": "user", "id": "other-user"})
        for index in range(1, 5)
    ]
    payloads.append(event_payload("evt-success", outcome="success"))
    for payload in payloads:
        assert ingest(client, payload).status_code == 201

    assert client.app.state.audit_repository.alerts == {}


def test_rule_ignores_non_user_actors(client: TestClient):
    for index in range(1, 6):
        response = ingest(
            client,
            event_payload(
                f"evt-service-actor-{index}",
                actor={"type": "service", "id": "user-123"},
            ),
        )
        assert response.status_code == 201

    assert client.app.state.audit_repository.alerts == {}


def test_rule_does_not_combine_failures_from_different_services(client: TestClient):
    for index in range(1, 5):
        response = ingest(client, event_payload(f"evt-primary-{index}"))
        assert response.status_code == 201
    response = ingest(
        client,
        event_payload("evt-other-service", source_id="other-auth-service"),
    )

    assert response.status_code == 201
    assert client.app.state.audit_repository.alerts == {}


def test_rule_excludes_failures_older_than_five_minutes(client: TestClient):
    for index in range(1, 5):
        assert ingest(client, event_payload(f"evt-old-{index}")).status_code == 201

    repository = client.app.state.audit_repository
    old_received_at = datetime.now(timezone.utc) - timedelta(minutes=6)
    for event_id, event in list(repository.events.items()):
        repository.events[event_id] = event.model_copy(
            update={"received_at": old_received_at}
        )

    assert ingest(client, event_payload("evt-current")).status_code == 201
    assert repository.alerts == {}


def test_event_and_alert_reads_require_dashboard_session(client: TestClient):
    assert client.get("/v1/events").status_code == 401
    assert client.get("/v1/alerts").status_code == 401


def test_authenticated_dashboard_can_list_and_get_events_and_alerts(client: TestClient):
    for index in range(1, 6):
        assert ingest(client, event_payload(f"evt-read-{index}")).status_code == 201
    login(client)

    events = client.get("/v1/events", params={"outcome": "failure", "limit": 4})
    assert events.status_code == 200
    assert len(events.json()) == 4
    event_id = events.json()[0]["id"]
    assert client.get(f"/v1/events/{event_id}").status_code == 200
    assert client.get(f"/v1/events/{uuid4()}").status_code == 404

    alerts = client.get("/v1/alerts")
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    alert_id = alerts.json()[0]["id"]
    assert client.get(f"/v1/alerts/{alert_id}").status_code == 200
    assert client.get(f"/v1/alerts/{uuid4()}").status_code == 404


def test_ingest_rejects_large_payload(client: TestClient):
    response = ingest(
        client,
        event_payload("evt-large", metadata={"padding": "x" * (64 * 1024)}),
    )
    assert response.status_code == 413


def test_sensitive_audit_api_responses_are_not_cached(client: TestClient):
    response = client.get("/v1/events")
    assert response.headers["cache-control"] == "no-store"


def test_dashboard_auth_precedes_storage_and_missing_storage_is_explicit():
    app = create_app(Settings(origin=ORIGIN))
    with TestClient(app, base_url=ORIGIN, headers={"origin": ORIGIN}) as client:
        client.app.state.entra.identity = lambda *_: ADMIN
        assert client.get("/v1/events").status_code == 401
        login(client)
        assert client.get("/v1/events").status_code == 503
