"""Storage interface implemented by the PostgreSQL data layer."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from backend.audit.schemas import (
    AlertRecord,
    AlertStatus,
    AlertWrite,
    Environment,
    EventRecord,
    EventWrite,
    Outcome,
)


@dataclass(frozen=True)
class ApiKeyScope:
    application_id: UUID
    environment: Environment
    key_id: str


@dataclass(frozen=True)
class FailedLoginStats:
    count: int
    first_received_at: datetime
    last_received_at: datetime


class EventConflict(Exception):
    """The same application/environment/event ID was submitted with different content."""


class AuditRepository(Protocol):
    """Methods the API needs from its database adapter."""

    def verify_api_key(self, raw_key: str) -> ApiKeyScope | None:
        """Verify hash, active status, and expiry; never return or log the secret."""
        ...

    def find_service_id(self, application_id: UUID, source_id: str) -> UUID | None:
        """Resolve only a service registered to the given application."""
        ...

    def insert_or_get_event(self, event: EventWrite) -> tuple[EventRecord, bool]:
        """Return (record, created); ignore received_at when comparing idempotent retries.

        Raise EventConflict if the same application/environment/event ID has
        different source content or resolves to a different service.
        """
        ...

    def get_event(self, event_id: UUID) -> EventRecord | None: ...

    def list_events(
        self,
        *,
        application_id: UUID | None,
        environment: Environment | None,
        service_id: UUID | None,
        action: str | None,
        outcome: Outcome | None,
        limit: int,
        offset: int,
    ) -> list[EventRecord]: ...

    def count_failed_logins(
        self,
        *,
        application_id: UUID,
        environment: Environment,
        service_id: UUID,
        actor_id: str,
        since: datetime,
        until: datetime,
    ) -> FailedLoginStats | None:
        """Count user.login/failure rows for user actors in the inclusive time interval."""
        ...

    def upsert_alert(self, alert: AlertWrite) -> AlertRecord:
        """Keep one open/acknowledged alert per app/environment/service/rule/actor."""
        ...

    def get_alert(self, alert_id: UUID) -> AlertRecord | None: ...

    def list_alerts(
        self,
        *,
        application_id: UUID | None,
        environment: Environment | None,
        status: AlertStatus | None,
        limit: int,
        offset: int,
    ) -> list[AlertRecord]: ...
