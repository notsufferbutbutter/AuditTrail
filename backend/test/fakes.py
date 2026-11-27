"""Small test doubles shared by API integration tests."""

from backend.audit.log_analytics import to_log_record
from backend.audit.schemas import EventRecord


class FakeLogAnalyticsIngestor:
    def __init__(self) -> None:
        self.records: list[dict[str, str]] = []

    def send_event(self, event: EventRecord) -> None:
        self.records.append(to_log_record(event))

    def close(self) -> None:
        pass
