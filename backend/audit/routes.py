"""HTTP endpoints for ingesting and querying audit events and alerts."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from starlette.concurrency import run_in_threadpool

from backend.audit.analysis import analyze_login_failure
from backend.audit.dependencies import get_repository, require_source_key
from backend.audit.repository import ApiKeyScope, AuditRepository, EventConflict
from backend.audit.schemas import (
    AlertRecord,
    AlertStatus,
    Environment,
    EventInput,
    EventRecord,
    EventWrite,
    Outcome,
)
from backend.auth.dependencies import current_user

router = APIRouter(prefix="/v1", tags=["audit"])
MAX_INGEST_BYTES = 64 * 1024


@router.post("/ingest", response_model=EventRecord)
async def ingest_event(
    payload: EventInput,
    request: Request,
    response: Response,
    scope: ApiKeyScope = Depends(require_source_key),
    repository: AuditRepository = Depends(get_repository),
) -> EventRecord:
    if len(await request.body()) > MAX_INGEST_BYTES:
        raise HTTPException(status_code=413, detail="Event payload is too large")

    service_id = await run_in_threadpool(
        repository.find_service_id,
        scope.application_id,
        payload.source_id,
    )
    if service_id is None:
        raise HTTPException(status_code=422, detail="Unknown source service")

    event = EventWrite(
        event_id=payload.event_id,
        application_id=scope.application_id,
        environment=scope.environment,
        service_id=service_id,
        action=payload.action,
        outcome=payload.outcome,
        actor=payload.actor.model_dump(),
        targets=[target.model_dump() for target in payload.targets],
        occurred_at=payload.occurred_at,
        received_at=datetime.now(timezone.utc),
        metadata=payload.metadata,
    )
    try:
        stored_event, created = await run_in_threadpool(
            repository.insert_or_get_event,
            event,
        )
    except EventConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="event_id already exists with different content",
        ) from exc

    response.status_code = 201 if created else 200
    if (
        stored_event.action == "user.login"
        and stored_event.outcome == "failure"
        and stored_event.actor.get("type") == "user"
    ):
        await analyze_login_failure(repository, stored_event)
    return stored_event


@router.get(
    "/events",
    response_model=list[EventRecord],
    dependencies=[Depends(current_user)],
)
def list_events(
    repository: AuditRepository = Depends(get_repository),
    application_id: UUID | None = None,
    environment: Environment | None = None,
    service_id: UUID | None = None,
    action: str | None = Query(default=None, max_length=200),
    outcome: Outcome | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[EventRecord]:
    return repository.list_events(
        application_id=application_id,
        environment=environment,
        service_id=service_id,
        action=action,
        outcome=outcome,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/events/{event_id}",
    response_model=EventRecord,
    dependencies=[Depends(current_user)],
)
def get_event(
    event_id: UUID,
    repository: AuditRepository = Depends(get_repository),
) -> EventRecord:
    event = repository.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get(
    "/alerts",
    response_model=list[AlertRecord],
    dependencies=[Depends(current_user)],
)
def list_alerts(
    repository: AuditRepository = Depends(get_repository),
    application_id: UUID | None = None,
    environment: Environment | None = None,
    status: AlertStatus | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[AlertRecord]:
    return repository.list_alerts(
        application_id=application_id,
        environment=environment,
        status=status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertRecord,
    dependencies=[Depends(current_user)],
)
def get_alert(
    alert_id: UUID,
    repository: AuditRepository = Depends(get_repository),
) -> AlertRecord:
    alert = repository.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
