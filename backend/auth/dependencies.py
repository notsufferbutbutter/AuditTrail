"""Authentication dependencies reused by protected API routes."""

from fastapi import HTTPException, Request
from pydantic import BaseModel

from backend.auth.sessions import COOKIE


class User(BaseModel):
    email: str


def current_user(request: Request) -> User:
    """Require a valid browser session."""
    email = request.app.state.sessions.email(request.cookies.get(COOKIE))
    if not email:
        raise HTTPException(status_code=401, detail="Sign in required")
    return User(email=email)


def same_origin(request: Request) -> None:
    """Protect browser POST requests against cross-site request forgery."""
    if request.headers.get("origin") != request.app.state.settings.origin:
        raise HTTPException(status_code=403, detail="Untrusted request origin")
