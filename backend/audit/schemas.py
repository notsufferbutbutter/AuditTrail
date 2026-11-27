"""Request and response models for audit events and alerts."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Environment = Literal["dev", "stg", "prod"]
Outcome = Literal["success", "failure"]
AlertStatus = Literal["open", "acknowledged", "resolved"]


class Actor(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str = Field(min_length=1, max_length=50)
    id: str = Field(min_length=1, max_length=200)


class EventInput(BaseModel):
    """Allowed data from an event source; app and environment come from its API key."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=100)
    source_id: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=200)
    outcome: Outcome
    actor: Actor
    targets: list[Actor] = Field(default_factory=list, max_length=100)
    occurred_at: datetime
    metadata: dict[str, Any] | None = None

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class EventWrite(BaseModel):
    event_id: str
    application_id: UUID
    environment: Environment
    service_id: UUID
    action: str
    outcome: Outcome
    actor: dict[str, Any]
    targets: list[dict[str, Any]]
    occurred_at: datetime
    received_at: datetime
    metadata: dict[str, Any] | None


class EventRecord(EventWrite):
    id: UUID


class AlertWrite(BaseModel):
    application_id: UUID
    environment: Environment
    service_id: UUID
    rule_code: str
    actor_id: str
    severity: str
    status: AlertStatus = "open"
    title: str
    description: str
    failure_count: int
    window_start: datetime
    window_end: datetime
    first_seen_at: datetime
    last_seen_at: datetime


class AlertRecord(AlertWrite):
    id: UUID
    created_at: datetime
    updated_at: datetime
