import logging
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles

from backend.audit.postgres import PostgresAuditRepository
from backend.audit.routes import router as audit_router
from backend.auth.dependencies import current_user
from backend.auth.entra import EntraTokens
from backend.auth.routes import router as auth_router
from backend.auth.sessions import Sessions
from backend.config import Settings
from backend.db import is_configured

logger = logging.getLogger("uvicorn.error")
frontend_dir = Path(__file__).resolve().parent.parent / "frontend/dist/audittrail/browser"


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings or Settings.from_env()
        app.state.sessions = Sessions(app.state.settings.session_seconds)
        app.state.entra = EntraTokens(app.state.settings)
        # Only the real server (settings read from the environment) connects automatically;
        # tests pass explicit Settings and choose their own repository.
        if settings is None and is_configured():
            app.state.audit_repository = PostgresAuditRepository()
            logger.info("Audit storage: PostgreSQL")
        else:
            logger.warning("Audit storage not configured (set DB_AUTH or DATABASE_URL)")
        logger.info("AuditTrail started")
        yield

    app = FastAPI(
        title="AuditTrail",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started = perf_counter()
        response = await call_next(request)
        if request.url.path.startswith(("/api/", "/v1/")):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info(
            "%s %s status=%d duration_ms=%.0f",
            request.method,
            request.url.path,
            response.status_code,
            (perf_counter() - started) * 1000,
        )
        return response

    @app.get("/health")
    def health():
        return {"status": "OK"}

    app.include_router(auth_router)

    @app.get("/api/documents", dependencies=[Depends(current_user)])
    def documents() -> list[dict]:
        # Protected document interface. Reading real documents comes in a later task.
        return []

    app.include_router(audit_router)

    # Registered last so that the API routes above are found first.
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    return app


app = create_app()
