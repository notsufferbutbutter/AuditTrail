import pytest

from backend.config import Settings


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("APP_ORIGIN", "http://localhost:4200")
    settings = Settings.from_env()
    assert settings.origin == "http://localhost:4200"
    assert not settings.secure_cookie


def test_app_origin_is_required(monkeypatch):
    monkeypatch.delenv("APP_ORIGIN", raising=False)
    with pytest.raises(ValueError, match="APP_ORIGIN"):
        Settings.from_env()


@pytest.mark.parametrize("origin", ["audittrail.example.com", "https://example.com/", "https://example.com/app"])
def test_origin_must_not_have_a_path(origin):
    with pytest.raises(ValueError):
        Settings(origin=origin)
