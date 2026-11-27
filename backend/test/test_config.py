import pytest

from backend.config import Settings


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("APP_ORIGIN", "http://localhost:4200")
    settings = Settings.from_env()
    assert settings.origin == "http://localhost:4200"
    assert settings.admin_role == "Admin"
    assert not settings.secure_cookie


def test_app_origin_is_required(monkeypatch):
    monkeypatch.delenv("APP_ORIGIN", raising=False)
    with pytest.raises(ValueError, match="APP_ORIGIN"):
        Settings.from_env()


@pytest.mark.parametrize("origin", ["audittrail.example.com", "https://example.com/", "https://example.com/app"])
def test_origin_must_not_have_a_path(origin):
    with pytest.raises(ValueError):
        Settings(origin=origin)


def test_log_analytics_requires_endpoint_and_dcr_id_together():
    with pytest.raises(ValueError, match="Set both LOG_ANALYTICS"):
        Settings(
            origin="https://audittrail.example.com",
            log_analytics_endpoint="https://example.ingest.monitor.azure.com",
        )


def test_log_analytics_endpoint_must_use_https():
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(
            origin="https://audittrail.example.com",
            log_analytics_endpoint="http://example.ingest.monitor.azure.com",
            log_analytics_dcr_id="dcr-id",
        )


def test_log_analytics_settings_are_read_from_environment(monkeypatch):
    monkeypatch.setenv("APP_ORIGIN", "https://audittrail.example.com")
    monkeypatch.setenv("LOG_ANALYTICS_ENDPOINT", "https://example.ingest.monitor.azure.com")
    monkeypatch.setenv("LOG_ANALYTICS_DCR_ID", "dcr-immutable-id")
    monkeypatch.setenv("LOG_ANALYTICS_STREAM_NAME", "Custom-AuditTrail_CL")

    settings = Settings.from_env()

    assert settings.log_analytics_configured
    assert settings.log_analytics_endpoint == "https://example.ingest.monitor.azure.com"
    assert settings.log_analytics_dcr_id == "dcr-immutable-id"
    assert settings.log_analytics_stream_name == "Custom-AuditTrail_CL"
