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
    # App role (Entra: audittrail-api -> App roles) that may read audit data.
    admin_role: str = "Admin"
    log_analytics_endpoint: str | None = None
    log_analytics_dcr_id: str | None = None
    log_analytics_stream_name: str = "Custom-AuditTrail_CL"

    def __post_init__(self):
        parts = urlsplit(self.origin)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path:
            raise ValueError("APP_ORIGIN must look like https://example.com (no path, no trailing slash)")
        if bool(self.log_analytics_endpoint) != bool(self.log_analytics_dcr_id):
            raise ValueError(
                "Set both LOG_ANALYTICS_ENDPOINT and LOG_ANALYTICS_DCR_ID to enable Log Analytics"
            )
        if self.log_analytics_endpoint:
            endpoint = urlsplit(self.log_analytics_endpoint)
            if endpoint.scheme != "https" or not endpoint.netloc:
                raise ValueError("LOG_ANALYTICS_ENDPOINT must be an HTTPS URL")

    @property
    def log_analytics_configured(self) -> bool:
        return bool(self.log_analytics_endpoint and self.log_analytics_dcr_id)

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
            log_analytics_endpoint=os.getenv("LOG_ANALYTICS_ENDPOINT") or None,
            log_analytics_dcr_id=os.getenv("LOG_ANALYTICS_DCR_ID") or None,
            log_analytics_stream_name=os.getenv(
                "LOG_ANALYTICS_STREAM_NAME",
                "Custom-AuditTrail_CL",
            ),
        )
