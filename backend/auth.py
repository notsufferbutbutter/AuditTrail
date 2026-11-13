import time
from secrets import token_urlsafe
from threading import Lock

COOKIE = "audittrail_session"


class Sessions:
    """Keeps logged-in users in memory. A restart of the server logs everyone out."""

    def __init__(self, lifetime_seconds: int):
        self.lifetime_seconds = lifetime_seconds
        self._sessions: dict[str, tuple[str, float]] = {}  # token -> (email, expires_at)
        self._lock = Lock()

    def create(self, email: str) -> str:
        token = token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions = {t: s for t, s in self._sessions.items() if s[1] > now}
            self._sessions[token] = (email, now + self.lifetime_seconds)
        return token

    def email(self, token: str | None) -> str | None:
        with self._lock:
            session = self._sessions.get(token or "")
        if session and session[1] > time.time():
            return session[0]
        return None

    def revoke(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)
