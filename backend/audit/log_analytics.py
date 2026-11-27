"""Send the minimum fields needed for cloud-side audit analysis to Azure Monitor."""

from datetime import datetime, timezone
from typing import Protocol

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

from backend.audit.schemas import EventRecord
from backend.config import Settings


class LogAnalyticsDeliveryError(Exception):
    """Azure Monitor rejected or could not receive an event."""


class LogAnalyticsIngestor(Protocol):
    def send_event(self, event: EventRecord) -> None: ...

    def close(self) -> None: ...


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def to_log_record(event: EventRecord) -> dict[str, str]:
    """Keep the Log Analytics copy small and limited to fields used by the rule."""
    received_at = _utc_timestamp(event.received_at)
    return {
        "TimeGenerated": received_at,
        "EventId": event.event_id,
        "ApplicationId": str(event.application_id),
        "Environment": event.environment,
        "ServiceId": str(event.service_id),
        "Action": event.action,
        "Outcome": event.outcome,
        "ActorType": str(event.actor["type"]),
        "ActorId": str(event.actor["id"]),
        "OccurredAt": _utc_timestamp(event.occurred_at),
        "ReceivedAt": received_at,
    }


class AzureMonitorLogAnalyticsIngestor:
    def __init__(self, settings: Settings):
        endpoint = settings.log_analytics_endpoint
        dcr_id = settings.log_analytics_dcr_id
        if not endpoint or not dcr_id:
            raise ValueError("Log Analytics endpoint and DCR ID are required")

        self._credential = DefaultAzureCredential()
        self._client = LogsIngestionClient(
            endpoint=endpoint,
            credential=self._credential,
        )
        self._dcr_id = dcr_id
        self._stream_name = settings.log_analytics_stream_name

    def send_event(self, event: EventRecord) -> None:
        try:
            self._client.upload(
                rule_id=self._dcr_id,
                stream_name=self._stream_name,
                logs=[to_log_record(event)],
            )
        except AzureError as exc:
            raise LogAnalyticsDeliveryError(
                "Azure Monitor Logs Ingestion API request failed"
            ) from exc

    def close(self) -> None:
        self._client.close()
        self._credential.close()


def create_log_analytics_ingestor(settings: Settings) -> LogAnalyticsIngestor | None:
    if not settings.log_analytics_configured:
        return None
    return AzureMonitorLogAnalyticsIngestor(settings)
