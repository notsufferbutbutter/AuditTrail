import logging
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.auth import COOKIE, Sessions
from backend.config import Settings
from backend.entra import EntraTokens

logger = logging.getLogger("uvicorn.error")
frontend_dir = Path(__file__).resolve().parent.parent / "frontend/dist/audittrail/browser"


class User(BaseModel):
    email: str


def current_user(request: Request) -> User:
    """Dependency for every protected endpoint: 401 unless the request has a valid session."""
    email = request.app.state.sessions.email(request.cookies.get(COOKIE))
    if not email:
        raise HTTPException(status_code=401, detail="Sign in required")
    return User(email=email)


def same_origin(request: Request) -> None:
    """Dependency for POST endpoints: only our own website may send them (CSRF protection)."""
    if request.headers.get("origin") != request.app.state.settings.origin:
        raise HTTPException(status_code=403, detail="Untrusted request origin")


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings or Settings.from_env()
        app.state.sessions = Sessions(app.state.settings.session_seconds)
        app.state.entra = EntraTokens(app.state.settings)
        logger.info("AuditTrail started")
        yield

    app = FastAPI(title="AuditTrail", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started = perf_counter()
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info("%s %s status=%d duration_ms=%.0f", request.method, request.url.path,
                    response.status_code, (perf_counter() - started) * 1000)
        return response

    @app.get("/health")
    def health():
        return {"status": "OK"}

    @app.get("/api/auth/config")
    def auth_config(request: Request):
        """Public settings the browser needs to start the Microsoft login."""
        config = request.app.state.settings
        return {
            "clientId": config.frontend_client_id,
            "authority": f"https://login.microsoftonline.com/{config.tenant_id}",
            "scope": config.api_scope,
            "redirectUri": config.origin + "/redirect.html",
        }

    @app.post("/api/auth/login", response_model=User, dependencies=[Depends(same_origin)])
    def login(request: Request, response: Response):
        """Exchange a Microsoft access token for our own session cookie."""
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Microsoft access token required",
                                headers={"WWW-Authenticate": "Bearer"})
        email = request.app.state.entra.identity(token)
        config = request.app.state.settings
        session_token = request.app.state.sessions.create(email)
        response.set_cookie(COOKIE, session_token, max_age=config.session_seconds, path="/",
                            secure=config.secure_cookie, httponly=True, samesite="lax")
        return User(email=email)

    @app.get("/api/auth/session", response_model=User)
    def session(user: User = Depends(current_user)):
        return user

    @app.post("/api/auth/logout", status_code=204, dependencies=[Depends(same_origin)])
    def logout(request: Request, response: Response):
        request.app.state.sessions.revoke(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")

    @app.get("/api/documents")
    def documents(user: User = Depends(current_user)) -> list[dict]:
        # Protected document interface. Reading real documents comes in a later task.
        return []

    # Registered last so that the API routes above are found first.
    if frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    return app


app = create_app()
