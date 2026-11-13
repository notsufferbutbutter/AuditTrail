import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    # Public address of the app, e.g. https://audittrail.azurewebsites.net (no trailing slash).
    origin: str
    # These IDs are public identifiers, not secrets.
    tenant_id: str = "0765b62a-fce8-4923-8bf6-390ec4b8308e"
    frontend_client_id: str = "0cb0559f-af7b-4744-a42f-181a5b118aa6"
    backend_client_id: str = "072934a6-6fa6-4a83-b2ef-ed86d55e6803"
    session_seconds: int = 3600

    def __post_init__(self):
        parts = urlsplit(self.origin)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path:
            raise ValueError("APP_ORIGIN must look like https://example.com (no path, no trailing slash)")

    @property
    def api_scope(self) -> str:
        return f"api://{self.backend_client_id}/access_as_user"

    @property
    def secure_cookie(self) -> bool:
        return self.origin.startswith("https://")

    @classmethod
    def from_env(cls) -> "Settings":
        if "APP_ORIGIN" not in os.environ:
            raise ValueError("Missing required environment variable: APP_ORIGIN")
        return cls(
            origin=os.environ["APP_ORIGIN"],
            tenant_id=os.getenv("ENTRA_TENANT_ID", cls.tenant_id),
            frontend_client_id=os.getenv("ENTRA_FRONTEND_CLIENT_ID", cls.frontend_client_id),
            backend_client_id=os.getenv("ENTRA_BACKEND_CLIENT_ID", cls.backend_client_id),
            session_seconds=int(os.getenv("SESSION_SECONDS", "3600")),
        )
