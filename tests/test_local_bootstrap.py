"""The Compose bootstrap creates one tenant and owner, then reuses them on later runs."""

from pathlib import Path
import runpy
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/local_bootstrap.py"


class FakeStore:
    instances = []

    def __init__(self, database_url, **_):
        self.database_url = database_url
        self.migrated = False
        self.bootstraps = []
        self.owners = []
        self.closed = False
        FakeStore.instances.append(self)

    def migrate(self):
        self.migrated = True
        return []

    def bootstrap_tenant(self, name, slug, tenant_id="", label="bootstrap", max_uses=0):
        self.bootstraps.append((name, slug, tenant_id, label, max_uses))
        return {"tenant": {"id": tenant_id or "11111111-1111-4111-8111-111111111111", "name": name, "slug": slug}}

    def create_tenant_owner(self, tenant_id, email, name, password_hash):
        from openaidr.server.store import Conflict

        if any(owner["email"] == email for owner in self.owners):
            raise Conflict("exists")
        owner = {"id": "owner", "tenant_id": tenant_id, "email": email, "name": name, "hash": password_hash}
        self.owners.append(owner)
        return owner

    def close(self):
        self.closed = True


@pytest.fixture
def bootstrap(monkeypatch, tmp_path):
    import openaidr.server.store as store

    monkeypatch.setattr(store, "Store", FakeStore)
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", "postgresql://openaidr:secret@db:5432/openaidr")
    monkeypatch.setenv("OPENAIDR_ADMIN_PASSWORD", "correct-horse-battery")
    monkeypatch.delenv("OPENAIDR_TENANT_ID", raising=False)
    monkeypatch.delenv("OPENAIDR_TENANT_ID_FILE", raising=False)
    FakeStore.instances.clear()
    main = runpy.run_path(str(SCRIPT))["main"]
    tenant_file = tmp_path / "tenant_id"
    return lambda *extra: main(["--email", "admin@localhost", "--tenant-file", str(tenant_file), *extra]), tenant_file


def test_first_run_creates_tenant_and_owner_and_reruns_reuse_them(bootstrap, capsys):
    run, tenant_file = bootstrap
    assert run() == 0
    assert tenant_file.read_text().strip() == "11111111-1111-4111-8111-111111111111"
    first = FakeStore.instances[-1]
    assert first.migrated and first.closed
    assert first.bootstraps == [("Local workspace", "local", "", "local", 0)]
    assert [owner["email"] for owner in first.owners] == ["admin@localhost"]
    assert first.owners[0]["hash"] != "correct-horse-battery"

    assert run() == 0
    second = FakeStore.instances[-1]
    assert second.bootstraps == [], "a bound tenant is reused without issuing another enrollment token"
    assert "already bound" in capsys.readouterr().out


def test_short_password_is_refused_before_touching_the_database(bootstrap, capsys, monkeypatch):
    run, tenant_file = bootstrap
    monkeypatch.setenv("OPENAIDR_ADMIN_PASSWORD", "short")
    assert run() == 1
    assert FakeStore.instances == []
    assert not tenant_file.exists()
    assert "at least 12 characters" in capsys.readouterr().err


@pytest.mark.parametrize("paid", [False, True])
def test_free_identity_is_bound_without_contacting_service_and_paid_identity_takes_precedence(bootstrap, monkeypatch, paid):
    import httpx
    from openaidr.server.config import from_env
    import openaidr.server.config as config

    installation = "22222222-2222-4222-8222-222222222222"
    monkeypatch.setenv("OPENAIDR_FREE_INSTALLATION_ID", installation)
    monkeypatch.setenv("OPENAIDR_FREE_DEVICE_ID", "33333333-3333-4333-8333-333333333333")
    monkeypatch.setenv("OPENAIDR_FREE_SECRET", "s" * 43)
    expected = str(uuid5(NAMESPACE_URL, "https://api.opensecura.ai/free/" + UUID(installation).hex))
    if paid:
        expected = "44444444-4444-4444-8444-444444444444"
        monkeypatch.setenv("OPENAIDR_TENANT_ID", expected)
        monkeypatch.setenv("OPENAIDR_INTELLIGENCE_ORIGIN", "https://api.opensecura.ai")
        monkeypatch.setenv("OPENAIDR_INTELLIGENCE_API_KEY", "oasc_" + "a" * 32 + "." + "b" * 43)
    cfg = from_env()
    credential = cfg.intelligence_api_key
    monkeypatch.setattr(config, "from_env", lambda: cfg)

    def forbidden(*args, **kwargs):
        pytest.fail("Bootstrap must not contact the Intelligence service")

    monkeypatch.setattr(httpx.Client, "__init__", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "__init__", forbidden)
    run, tenant_file = bootstrap
    assert run() == 0
    assert tenant_file.read_text().strip() == expected
    assert FakeStore.instances[-1].bootstraps[0][2] == expected
    assert cfg.intelligence_api_key == credential
    assert run() == 0
    assert FakeStore.instances[-1].bootstraps == []


def test_free_identity_mismatch_preserves_existing_workspace(bootstrap, monkeypatch):
    monkeypatch.setenv("OPENAIDR_FREE_INSTALLATION_ID", "22222222-2222-4222-8222-222222222222")
    monkeypatch.setenv("OPENAIDR_FREE_DEVICE_ID", "33333333-3333-4333-8333-333333333333")
    monkeypatch.setenv("OPENAIDR_FREE_SECRET", "s" * 43)
    run, tenant_file = bootstrap
    original = "44444444-4444-4444-8444-444444444444\n"
    tenant_file.write_text(original)
    with pytest.raises(ValueError, match="does not match the existing local workspace"):
        run()
    assert tenant_file.read_text() == original
    assert FakeStore.instances[-1].bootstraps == []
    assert FakeStore.instances[-1].owners == []
    assert FakeStore.instances[-1].closed
