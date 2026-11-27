"""In-memory browser session management."""

import time
from secrets import token_urlsafe
from threading import Lock

COOKIE = "audittrail_session"


class Sessions:
    """Keeps the Microsoft access token of each signed-in browser on the server.

    The browser only holds a random session ID (HttpOnly cookie), never the token itself.
    A restart of the server logs everyone out.
    """

    def __init__(self, lifetime_seconds: int):
        self.lifetime_seconds = lifetime_seconds
        # session ID -> (access token, expires_at)
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = Lock()

    def create(self, access_token: str) -> str:
        session_id = token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions = {s: v for s, v in self._sessions.items() if v[1] > now}
            self._sessions[session_id] = (access_token, now + self.lifetime_seconds)
        return session_id

    def access_token(self, session_id: str | None) -> str | None:
        """Return the stored Microsoft token of a valid session, otherwise None."""
        with self._lock:
            session = self._sessions.get(session_id or "")
        if session and session[1] > time.time():
            return session[0]
        return None

    def revoke(self, session_id: str | None) -> None:
        with self._lock:
            self._sessions.pop(session_id or "", None)