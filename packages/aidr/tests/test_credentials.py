"""Standalone credentials retain identity and verify service replies before activation."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import ssl
import threading
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import httpx
import pytest

from aidr import credentials
from aidr._vendor.openaidr_api_client.contracts.capabilities import CAPABILITIES


TOKEN = "oasc_" + "a" * 32 + "." + "b" * 43
TENANT = "11111111-1111-4111-8111-111111111111"


def saved(path):
    return json.loads(path.read_text())


def free_status(tenant):
    return {"tenant_id": tenant, "plan": "free", "status": "available", "guardrail_configured": True,
            "guardrail_available": True, "reset_at": None, "credit_status": "active", "credits_per_usd": "100"}


def capabilities(tenant):
    return {"tenant_id": tenant, "build": "test", "capabilities": {name: "configured" for name in CAPABILITIES},
            "provider_access": "not_checked", "investigation_worker": "not_checked"}


def free_service(path, requests):
    def handle(request):
        requests.append(request)
        identity = saved(path)["free"]
        tenant = str(uuid5(NAMESPACE_URL, credentials.ORIGIN + "/free/" + UUID(identity["installation_id"]).hex))
        if request.url.path == "/v1/free/enroll":
            assert request.method == "POST"
            assert json.loads(request.content) == {key: identity[key] for key in ("installation_id", "device_id", "secret")}
        else:
            assert request.url.path == "/v1/free/status" and request.method == "GET"
            assert request.headers["x-opensecura-tenant-id"] == tenant
            assert request.headers["authorization"] == "Bearer oasc_" + UUID(identity["installation_id"]).hex + "." + identity["secret"]
        return httpx.Response(200, json=free_status(tenant))
    return httpx.MockTransport(handle)


@pytest.mark.parametrize("platform,expected", [
    ("darwin", "Library/Application Support/aidr/credentials.json"),
    ("linux", ".config/aidr/credentials.json"),
    ("win32", "AppData/Roaming/aidr/credentials.json"),
])
def test_default_store_is_separate_from_app_and_sensor(monkeypatch, tmp_path, platform, expected):
    monkeypatch.setattr(credentials.sys, "platform", platform)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert credentials.default_path() == tmp_path / expected


@pytest.mark.parametrize("origin", [credentials.ORIGIN, "https://service.example.test"])
def test_free_identity_is_durable_before_request_and_status_is_verified(tmp_path, origin):
    path = tmp_path / "aidr/credentials.json"
    requests = []
    transport = free_service(path, requests)
    result = credentials.enroll_free(path, base_url=origin, transport=transport)
    assert [r.url.path for r in requests] == ["/v1/free/enroll", "/v1/free/status"]
    assert all(str(r.url).startswith(origin) for r in requests)
    assert result["authenticated"] and result["mode"] == "free"
    assert credentials.status(path, transport=transport) == result
    state = saved(path)
    connection = credentials.load_connection(path)
    assert connection.tenant_id == result["tenant_id"]
    assert connection.api_key not in repr(connection)
    assert connection.api_key not in json.dumps(result)
    assert state["free"]["secret"] not in json.dumps(result)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


def test_free_retry_recovers_exact_identity_after_lost_reply(tmp_path):
    path = tmp_path / "credentials.json"
    calls = []

    def lost(request):
        calls.append(json.loads(request.content))
        assert saved(path)["active"] is None
        raise httpx.ReadTimeout("private " + saved(path)["free"]["secret"])

    with pytest.raises(credentials.CredentialError, match="same account") as caught:
        credentials.enroll_free(path, transport=httpx.MockTransport(lost))
    original = saved(path)
    assert original["free"]["secret"] not in str(caught.value)
    assert credentials.status(path) == {"authenticated": False, "free_identity_retained": True}
    with pytest.raises(credentials.CredentialError, match="aidr enroll --free"):
        credentials.load_connection(path)
    requests = []
    credentials.enroll_free(path, transport=free_service(path, requests))
    assert saved(path)["free"] == original["free"]
    assert json.loads(requests[0].content) == calls[0]


@pytest.mark.parametrize("failure", ["enroll_tenant", "status_tenant", "status_error", "redirect"])
def test_failed_free_verification_preserves_active_credentials(tmp_path, failure):
    path = tmp_path / "credentials.json"
    credentials.login(path, TOKEN, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=capabilities(TENANT))))
    active = saved(path)["active"]
    requests = []
    service = free_service(path, requests)

    def reject(request):
        response = service.handler(request)
        if failure == "redirect":
            return httpx.Response(307, headers={"Location": "https://unrelated.example/"})
        if (failure == "enroll_tenant" and request.url.path.endswith("enroll")) or (
                failure == "status_tenant" and request.url.path.endswith("status")):
            return httpx.Response(200, json=free_status(str(uuid4())))
        if failure == "status_error" and request.url.path.endswith("status"):
            return httpx.Response(503, text=TOKEN)
        return response

    with pytest.raises(credentials.CredentialError):
        credentials.enroll_free(path, transport=httpx.MockTransport(reject))
    assert saved(path)["active"] == active
    assert credentials.load_connection(path).api_key == TOKEN
    assert len(requests) == (1 if failure in ("enroll_tenant", "redirect") else 2)


def test_login_and_logout_retain_free_account_for_reenrollment(tmp_path):
    path = tmp_path / "credentials.json"
    requests = []
    credentials.enroll_free(path, transport=free_service(path, requests))
    identity = saved(path)["free"]

    def discover(request):
        assert request.url.path == "/v1/capabilities"
        assert "x-opensecura-tenant-id" not in request.headers
        assert request.headers["authorization"] == "Bearer " + TOKEN
        value = capabilities(TENANT)
        value["build"] = TOKEN
        value["capabilities"]["extension"] = "configured"
        return httpx.Response(200, json=value)

    result = credentials.login(path, TOKEN, transport=httpx.MockTransport(discover))
    assert result["mode"] == "api_key" and result["tenant_id"] == TENANT
    assert "extension" not in result["capabilities"] and TOKEN not in json.dumps(result)
    assert saved(path)["free"] == identity
    assert credentials.logout(path) == {"authenticated": False, "free_identity_retained": True}
    assert saved(path)["free"] == identity and saved(path)["active"] is None
    credentials.enroll_free(path, transport=free_service(path, requests))
    assert saved(path)["free"] == identity


@pytest.mark.parametrize("lost_reply", [False, True])
def test_unassigned_key_claim_is_persisted_and_lost_reply_is_recovered(tmp_path, lost_reply):
    path = tmp_path / "credentials.json"
    bound = None
    requests = []

    def service(request):
        nonlocal bound
        requests.append(request)
        assert request.method == "GET" and request.url.path == "/v1/capabilities"
        tenant = request.headers.get("x-opensecura-tenant-id")
        if bound is None and tenant is None:
            return httpx.Response(401, json={"error": "tenant_assignment_required"})
        if bound is None:
            pending = saved(path)["pending_login"]
            assert pending["tenant_id"] == tenant and pending["key_id"] == TOKEN[5:37]
            assert saved(path)["active"] is None
            bound = tenant
            if lost_reply:
                raise httpx.ReadTimeout("private transport data")
        return httpx.Response(200, json=capabilities(bound))

    transport = httpx.MockTransport(service)
    if lost_reply:
        with pytest.raises(credentials.CredentialError):
            credentials.login(path, TOKEN, transport=transport)
        assert saved(path)["pending_login"]["tenant_id"] == bound
    result = credentials.login(path, TOKEN, transport=transport)
    assert result["tenant_id"] == bound and saved(path)["pending_login"] is None
    assert sum("x-opensecura-tenant-id" in request.headers for request in requests) == 1


@pytest.mark.parametrize("failure", ["timeout", "tenant_mismatch"])
def test_pending_claim_reuses_tenant_and_preserves_existing_account(tmp_path, failure):
    path = tmp_path / "credentials.json"
    credentials.enroll_free(path, transport=free_service(path, []))
    original = saved(path)
    claims = []

    def service(request):
        tenant = request.headers.get("x-opensecura-tenant-id")
        if tenant is None:
            return httpx.Response(401, json={"error": "tenant_assignment_required"})
        claims.append(tenant)
        if len(claims) == 1:
            if failure == "timeout":
                raise httpx.ReadTimeout("private")
            return httpx.Response(200, json=capabilities(str(uuid4())))
        return httpx.Response(200, json=capabilities(tenant))

    transport = httpx.MockTransport(service)
    with pytest.raises(credentials.CredentialError):
        credentials.login(path, TOKEN, transport=transport)
    assert saved(path)["active"] == original["active"] and saved(path)["free"] == original["free"]
    credentials.login(path, TOKEN, transport=transport)
    assert len(claims) == 2 and claims[0] == claims[1]


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"error": "invalid_api_key"}),
    httpx.Response(401, json={"error": "tenant_assignment_required", "extra": True}),
    httpx.Response(403, json={"error": "tenant_assignment_required"}),
    httpx.Response(302, headers={"Location": "https://unrelated.example/"}),
    httpx.Response(200, content=b"bad json"),
    httpx.Response(200, content=b"x" * ((16 << 10) + 1)),
    httpx.Response(200, json=capabilities(TENANT), headers={"Content-Encoding": "custom"}),
])
def test_rejected_discovery_never_claims_or_changes_active_connection(tmp_path, response):
    path = tmp_path / "credentials.json"
    credentials.enroll_free(path, transport=free_service(path, []))
    before = path.read_bytes()
    requests = []

    def reject(request):
        requests.append(request)
        return response

    with pytest.raises(credentials.CredentialError):
        credentials.login(path, TOKEN, transport=httpx.MockTransport(reject))
    assert len(requests) == 1 and path.read_bytes() == before


@pytest.mark.parametrize("operation", ["enroll_free", "login", "load_connection", "status", "logout"])
def test_corrupt_state_is_never_reset(tmp_path, operation):
    path = tmp_path / "credentials.json"
    path.write_text('{"secret": "private malformed state"}')
    path.chmod(0o600)
    before = path.read_bytes()
    with pytest.raises(credentials.CredentialError, match="invalid") as caught:
        getattr(credentials, operation)(path, *([TOKEN] if operation == "login" else []))
    assert "private malformed" not in str(caught.value)
    assert path.read_bytes() == before


def test_duplicate_state_fields_are_rejected_without_rotating_identity(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text('{"version":1,"free":null,"active":null,"pending_login":null,"free":null}')
    path.chmod(0o600)
    before = path.read_bytes()
    with pytest.raises(credentials.CredentialError, match="invalid"):
        credentials.enroll_free(path, transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected request")))
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions and symbolic links")
@pytest.mark.parametrize("target", ["file", "lock", "directory", "permissions", "hardlink"])
def test_unsafe_store_is_rejected_before_any_request(tmp_path, target):
    private = tmp_path / "aidr"
    private.mkdir(mode=0o700)
    path = private / "credentials.json"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    victim.chmod(0o600)
    if target in ("file", "lock"):
        (path if target == "file" else path.with_name(path.name + ".lock")).symlink_to(victim)
    elif target == "directory":
        linked = tmp_path / "linked"
        linked.symlink_to(private, target_is_directory=True)
        path = linked / "credentials.json"
    elif target == "permissions":
        private.chmod(0o755)
    else:
        os.link(victim, path)
    with pytest.raises(credentials.CredentialError):
        credentials.enroll_free(path, transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected network request")))
    assert victim.read_text() == "unchanged"


def test_free_identity_cannot_be_reused_at_another_service(tmp_path):
    path = tmp_path / "credentials.json"
    credentials.enroll_free(path, transport=free_service(path, []))
    before = path.read_bytes()
    with pytest.raises(credentials.CredentialError, match="separate --config"):
        credentials.enroll_free(path, base_url="https://another.example.test", transport=httpx.MockTransport(
            lambda _: pytest.fail("Unexpected request")))
    assert path.read_bytes() == before


def test_concurrent_enrollment_does_not_create_another_identity(tmp_path):
    path = tmp_path / "credentials.json"
    started, release = threading.Event(), threading.Event()
    base = free_service(path, [])

    def service(request):
        if request.url.path.endswith("enroll"):
            started.set()
            assert release.wait(5)
        return base.handler(request)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(credentials.enroll_free, path, transport=httpx.MockTransport(service))
        assert started.wait(5)
        identity = saved(path)["free"]
        try:
            with pytest.raises(credentials.CredentialError, match="another process"):
                credentials.enroll_free(path, transport=httpx.MockTransport(lambda _: pytest.fail("Concurrent request")))
        finally:
            release.set()
        assert first.result()["authenticated"]
    assert saved(path)["free"] == identity


def test_relative_trust_bundle_survives_cwd_change_and_logout_survives_missing_bundle(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    ca_file = tmp_path / "trust.pem"
    ca_file.write_text(ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0]))
    monkeypatch.chdir(tmp_path)
    credentials.login(path, TOKEN, ca_file="trust.pem", transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=capabilities(TENANT))))
    assert saved(path)["active"]["ca_file"] == str(ca_file)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert credentials.load_connection(path).ca_file == str(ca_file)
    ca_file.unlink()
    with pytest.raises(credentials.CredentialError, match="trust bundle"):
        credentials.load_connection(path)
    assert credentials.logout(path)["authenticated"] is False
    assert saved(path)["active"] is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory synchronization")
def test_new_directories_are_durable_before_enrollment_request(tmp_path, monkeypatch):
    path = tmp_path / "config/aidr/credentials.json"
    synced = []
    synchronize = credentials._sync_directory

    def record(directory):
        synchronize(directory)
        synced.append(directory)

    monkeypatch.setattr(credentials, "_sync_directory", record)
    service = free_service(path, [])

    def verify_durability(request):
        assert {tmp_path, tmp_path / "config", path.parent} <= set(synced)
        return service.handler(request)

    credentials.enroll_free(path, transport=httpx.MockTransport(verify_durability))


def test_failed_atomic_save_keeps_active_credentials(tmp_path, monkeypatch):
    path = tmp_path / "credentials.json"
    credentials.enroll_free(path, transport=free_service(path, []))
    before = path.read_bytes()

    def fail_replace(*args):
        raise OSError("private filesystem detail")

    monkeypatch.setattr(credentials.os, "replace", fail_replace)
    with pytest.raises(credentials.CredentialError, match="credential store") as caught:
        credentials.login(path, TOKEN, transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json=capabilities(TENANT))))
    assert path.read_bytes() == before
    assert "private filesystem detail" not in str(caught.value)
    assert sorted(file.name for file in tmp_path.iterdir()) == ["credentials.json", "credentials.json.lock"]
