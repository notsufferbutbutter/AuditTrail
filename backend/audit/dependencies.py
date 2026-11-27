"""Request dependencies for audit routes."""

from fastapi import HTTPException, Request

from backend.audit.log_analytics import LogAnalyticsIngestor
from backend.audit.repository import ApiKeyScope, AuditRepository


def get_repository(request: Request) -> AuditRepository:
    repository = getattr(request.app.state, "audit_repository", None)
    if repository is None:
        raise HTTPException(status_code=503, detail="Audit storage is unavailable")
    return repository


def get_log_analytics_ingestor(request: Request) -> LogAnalyticsIngestor:
    ingestor = getattr(request.app.state, "log_analytics_ingestor", None)
    if ingestor is None:
        raise HTTPException(
            status_code=503,
            detail="Log Analytics ingestion is not configured",
        )
    return ingestor


def require_source_key(request: Request) -> ApiKeyScope:
    raw_key = request.headers.get("X-API-Key")
    if not raw_key:
        raise HTTPException(status_code=401, detail="API key required")

    scope = get_repository(request).verify_api_key(raw_key)
    if scope is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return scope
