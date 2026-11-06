"""The published client runs without the private cloud implementation."""

import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from test_store import db  # noqa: F401


ROOT = Path(__file__).resolve().parents[1]


def test_public_server_and_cli_without_cloud_package(tmp_path):
    patterns = json.loads((ROOT / "opensource/publication.json").read_text())["exclude"] if (ROOT / "opensource/publication.json").exists() else []

    def excluded(directory, names):
        return [name for name in names if name in ("platform", "__pycache__", "web")
                or str((Path(directory) / name).relative_to(ROOT)) in patterns]

    shutil.copytree(ROOT / "src/openaidr", tmp_path / "openaidr",
                    ignore=excluded)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENAIDR_")}
    environment["PYTHONPATH"] = str(tmp_path)
    result = subprocess.run([sys.executable, "-c", """
from unittest.mock import Mock
from fastapi.testclient import TestClient
from openaidr.server.app import create_app
from openaidr.server.config import Config, PLATFORM_AVAILABLE, from_env

from openaidr.server import summary_report_sharing
from openaidr.server.store import Store
assert callable(summary_report_sharing.read)
assert not PLATFORM_AVAILABLE
assert not hasattr(Store, "create_admin")
assert not hasattr(Store, "get_platform_overview")
from openaidr.server import skill_worker
worker_client = Mock()
assert skill_worker.model_environment("static", worker_client) == {}
for operation in (
    lambda: skill_worker.run_once(worker_client, "fixture-profile", binary="must-not-run"),
    lambda: skill_worker.model_environment("llm", worker_client),
):
    try:
        operation()
    except ValueError as error:
        assert "private platform package" in str(error)
    else:
        raise AssertionError("Legacy scanner must not run without the private package")
worker_client.post.assert_not_called()
cfg = from_env()
assert cfg.services == {"ingest": True, "api": True, "detect": True}
cfg.database_url = "postgresql://unused/client"
cfg.validate()
backend = Mock()
client = TestClient(create_app(cfg, backend))
assert client.get("/healthz").status_code == 200
assert client.get("/api/v1/auth/config").json()["mode"] == "local"
assert client.get("/api/v1/auth/me").status_code == 401
for path in ("/admin/v1/tenants", "/admin/v1/auth/config", "/platform/admins",
             "/management/v1/provisioning/verify", "/reporting/v1/summary-reports"):
    assert client.get(path).status_code == 404, path
    assert client.post(path, json={}).status_code == 404, path
backend.create_tenant.assert_not_called()
for values in ({"services": {"admin": True}}, {"cloud_management_enabled": True},
               {"auth_mode": "cloud_google"}, {"api_operations_enabled": True}):
    try:
        Config(database_url="postgresql://unused/client", **values).validate()
    except ValueError as error:
        assert "private platform package" in str(error)
    else:
        raise AssertionError(values)
"""], cwd=tmp_path, env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    help_result = subprocess.run([sys.executable, "-m", "openaidr.server.cli", "--help"],
                                 cwd=tmp_path, env=environment, capture_output=True, text=True)
    assert help_result.returncode == 0, help_result.stderr
    assert "admin" not in help_result.stdout
    assert "tenant" in help_result.stdout


def test_local_authentication_and_sessions_survive_platform_separation(db):
    from fastapi.testclient import TestClient
    from openaidr.server import auth, store
    from openaidr.server.app import create_app
    from openaidr.server.config import Config
    from test_store import tenant

    workspace = tenant(db)
    user = db.create_user(workspace["id"], "local@example.test", "Local", auth.hash_password("password123"), "owner")
    cfg = Config(database_url=db.url)
    cfg.set_services("api")
    client = TestClient(create_app(cfg, db), headers={auth.CSRF_HEADER: "1", "Origin": cfg.public_url})
    assert client.post("/api/v1/auth/login", json={"email": user["email"], "password": "incorrect"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": user["email"], "password": "password123"}).status_code == 200
    token = client.cookies.get(auth.CONSOLE_COOKIE)
    assert client.get("/api/v1/auth/me").json()["user"]["id"] == user["id"]
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401
    with pytest.raises(store.NotFound):
        db.get_session(token)


def test_private_operator_imports_keep_module_identity_and_source_paths():
    pytest.importorskip("openaidr.platform")
    for name in ("device_credentials", "broker_clients", "readiness_reporter", "deployments", "provisioning"):
        legacy = importlib.import_module("openaidr.server." + name)
        current = importlib.import_module("openaidr.platform." + name)
        assert legacy is current
        assert Path(legacy.__file__).parent.name == "platform"
