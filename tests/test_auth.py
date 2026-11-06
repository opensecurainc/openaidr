import pytest
from openaidr.server.auth import hash_password, check_password
from openaidr.server.config import PLATFORM_AVAILABLE, from_env


def test_password_bcrypt_roundtrip():
    hashed = hash_password("correct horse battery")
    assert hashed.startswith("$2b$10$")
    assert check_password(hashed, "correct horse battery")
    assert not check_password(hashed, "wrong")
    assert not check_password("invalid hash", "anything")
    with pytest.raises(ValueError):
        hash_password("short")


@pytest.mark.skipif(not PLATFORM_AVAILABLE, reason="the admin service needs the private platform package")
def test_server_config(monkeypatch):
    monkeypatch.delenv("OPENAIDR_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("OPENAIDR_COOKIE_SECURE_FILE", raising=False)
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", "postgresql://localhost/test")
    monkeypatch.setenv("OPENAIDR_PUBLIC_URL", "https://example.test/")
    monkeypatch.setenv("OPENAIDR_ADMIN_PUBLIC_URL", "https://admin.example.test/")
    monkeypatch.setenv("OPENAIDR_SERVICES", "ingest, detect")
    monkeypatch.delenv("OPENAIDR_SESSION_DETECTION_SCHEDULING", raising=False)
    monkeypatch.delenv("OPENAIDR_SESSION_DETECTION_SCHEDULING_FILE", raising=False)
    monkeypatch.delenv("OPENAIDR_SESSION_INVESTIGATOR_BINARY", raising=False)
    monkeypatch.delenv("OPENAIDR_SESSION_INVESTIGATOR_BINARY_FILE", raising=False)
    config = from_env()
    assert config.session_detection_scheduling is True
    assert config.session_investigator_binary == ""
    monkeypatch.setenv("OPENAIDR_SESSION_DETECTION_SCHEDULING", "false")
    assert from_env().session_detection_scheduling is False
    monkeypatch.setenv("OPENAIDR_SESSION_INVESTIGATOR_BINARY", "/opt/openaidr/codex")
    assert from_env().session_investigator_binary == "/opt/openaidr/codex"
    assert not config.cookie_secure
    assert config.secure_cookie() and config.public_url == "https://example.test"
    assert config.browser_origin(admin=True) == "https://admin.example.test"
    assert config.enabled("detect") and not config.enabled("admin")
    config.validate()
    config.set_services("bogus")
    with pytest.raises(ValueError):
        config.validate()


def test_tenant_ignores_provider_key_environment(monkeypatch, tmp_path):
    for name in ("OPENAI_API_KEY", "OPENAIDR_OPENAI_API_KEY", "OPENAIDR_OPENAI_API_KEY_FILE"):
        monkeypatch.setenv(name, "private-provider-value")
    assert from_env().openai_api_key == ""
    assert "private-provider-value" not in repr(from_env())


@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.test",
        "https://example.test/console",
        "https://example.test?",
        "//example.test",
        "file:///server",
        "https://example.test:bad",
        "https://example.test#",
        "http://[::1]suffix:8080",
    ],
)
def test_server_rejects_invalid_configured_browser_origin(monkeypatch, url):
    monkeypatch.setenv("OPENAIDR_PUBLIC_URL", url)
    with pytest.raises(ValueError, match="OPENAIDR_PUBLIC_URL must be"):
        from_env().browser_origin()
