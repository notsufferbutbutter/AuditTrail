"""Analysis rules that turn ingested events into persisted alerts."""

from datetime import timedelta

from starlette.concurrency import run_in_threadpool

from backend.audit.repository import AuditRepository
from backend.audit.schemas import AlertWrite, EventRecord

LOGIN_FAILURE_RULE = "repeated_login_failures"
LOGIN_FAILURE_THRESHOLD = 5
LOGIN_FAILURE_WINDOW = timedelta(minutes=5)


async def analyze_login_failure(
    repository: AuditRepository,
    event: EventRecord,
) -> None:
    """Create/update an alert when five user login failures share a five-minute window."""
    window_start = event.received_at - LOGIN_FAILURE_WINDOW
    stats = await run_in_threadpool(
        repository.count_failed_logins,
        application_id=event.application_id,
        environment=event.environment,
        service_id=event.service_id,
        actor_id=str(event.actor["id"]),
        since=window_start,
        until=event.received_at,
    )
    if stats is None or stats.count < LOGIN_FAILURE_THRESHOLD:
        return

    alert = AlertWrite(
        application_id=event.application_id,
        environment=event.environment,
        service_id=event.service_id,
        rule_code=LOGIN_FAILURE_RULE,
        actor_id=str(event.actor["id"]),
        severity="high",
        status="open",
        title="Repeated login failures",
        description=(
            f"{stats.count} failed login attempts for actor "
            f"{event.actor['id']} on service {event.service_id} "
            "within five minutes."
        ),
        failure_count=stats.count,
        window_start=window_start,
        window_end=event.received_at,
        first_seen_at=stats.first_received_at,
        last_seen_at=stats.last_received_at,
    )
    await run_in_threadpool(repository.upsert_alert, alert)
