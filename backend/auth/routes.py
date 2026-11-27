"""Browser login, session, and logout endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from backend.auth.dependencies import User, current_user, same_origin
from backend.auth.sessions import COOKIE

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.get("/config")
def auth_config(request: Request):
    """Public settings the browser needs to start the Microsoft login."""
    config = request.app.state.settings
    return {
        "clientId": config.frontend_client_id,
        "authority": f"https://login.microsoftonline.com/{config.tenant_id}",
        "scope": config.api_scope,
        "redirectUri": config.origin + "/redirect.html",
    }


@router.post("/login", response_model=User, dependencies=[Depends(same_origin)])
def login(request: Request, response: Response) -> User:
    """Exchange a Microsoft access token for our own session cookie."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Microsoft access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    email = request.app.state.entra.identity(token)
    config = request.app.state.settings
    session_token = request.app.state.sessions.create(email)
    response.set_cookie(
        COOKIE,
        session_token,
        max_age=config.session_seconds,
        path="/",
        secure=config.secure_cookie,
        httponly=True,
        samesite="lax",
    )
    return User(email=email)


@router.get("/session", response_model=User)
def session(user: User = Depends(current_user)) -> User:
    return user


@router.post("/logout", status_code=204, dependencies=[Depends(same_origin)])
def logout(request: Request, response: Response) -> None:
    request.app.state.sessions.revoke(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
