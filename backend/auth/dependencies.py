"""Authentication dependencies reused by protected API routes."""

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from backend.auth.sessions import COOKIE


class User(BaseModel):
    email: str
    roles: list[str] = []


def current_user(request: Request) -> User:
    """Require a valid session AND validate its Microsoft access token on every request."""
    token = request.app.state.sessions.access_token(request.cookies.get(COOKIE))
    if not token:
        raise HTTPException(status_code=401, detail="Sign in required")
    # identity() checks signature, issuer, audience, expiry and scope again (401/403 if invalid).
    identity = request.app.state.entra.identity(token)
    return User(email=identity.email, roles=sorted(identity.roles))


def require_admin(request: Request, user: User = Depends(current_user)) -> User:
    """Only users with the Entra app role may read audit data."""
    if request.app.state.settings.admin_role not in user.roles:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def same_origin(request: Request) -> None:
    """Protect browser POST requests against cross-site request forgery."""
    if request.headers.get("origin") != request.app.state.settings.origin:
        raise HTTPException(status_code=403, detail="Untrusted request origin")