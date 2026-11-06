"""Real HTTPS service boundaries for the shared tenant connection."""

import asyncio
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import socket
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import httpx
from openaidr_api.providers import web_risk as provider_links
import pytest
from starlette.responses import JSONResponse, RedirectResponse
import uvicorn

from openaidr_api.threat_intel import keys
from openaidr_api.app import Config as ServiceConfig, create_app as create_service
from openaidr.server import auth, hook_policy, osv, skill_intel_proxy
from openaidr.server.app import create_app
from openaidr.server.config import Config, from_env
from openaidr_api_client.client import Connection, IntelligenceClient, SyncIntelligenceClient, Unavailable
from openaidr_api_client.clients.threat_intel import ThreatIntelClient
from test_hook_policy import payload
from test_store import db, sensor, tenant
from intelligence_service_fixtures import BAD, ThreatProvider as Provider

KEY = "oati_" + "a" * 32 + "." + "b" * 43
TENANT = str(uuid4())
ORIGIN = "https://intelligence.example.com"
QUERY = {"package": {"ecosystem": "npm", "name": "example"}, "version": "1.0.0"}


@pytest.fixture
def connection_environment(monkeypatch):
    for family in ("THREAT_INTEL", "INTELLIGENCE"):
        for name in ("ORIGIN", "ORIGIN_FILE", "API_KEY", "API_KEY_FILE", "CA_FILE"):
            monkeypatch.delenv("OPENAIDR_" + family + "_" + name, raising=False)
    for name in ("OPENAIDR_OPENAI_API_KEY", "OPENAIDR_OPENAI_API_KEY_FILE", "OPENAI_API_KEY",
                 "OPENAIDR_JEV_API_KEY", "OPENAIDR_JEV_API_KEY_FILE", "TYPESAFE_API_KEY",
                 "OPENAIDR_DATABASE_URL_FILE", "OPENAIDR_INTELLIGENCE_KEYS_KEY", "OPENAIDR_INTELLIGENCE_KEYS_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", "unused")
    monkeypatch.setenv("OPENAIDR_TENANT_ID", TENANT)


def test_connection_aliases_secret_files_and_configuration_readiness(connection_environment, monkeypatch, tmp_path):
    assert Connection.from_config(from_env()) is None
    secret = tmp_path / "tenant.key"
    secret.write_text(KEY + "\n")
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_ORIGIN", ORIGIN)
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_API_KEY_FILE", str(secret))
    cfg = from_env()
    cfg.set_services("ingest,detect")
    cfg.validate()
    connection = Connection.from_config(cfg)
    assert connection == Connection(ORIGIN, KEY, TENANT)
    assert KEY not in repr(connection) and KEY not in repr(cfg)
    assert not cfg.openai_api_key
    encryption = tmp_path / "storage.key"
    encryption.write_bytes(Fernet.generate_key() + b"\n")
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_KEYS_KEY_FILE", str(encryption))
    stored = from_env()
    stored.set_services("ingest,detect")
    stored.validate()
    assert stored.intelligence_keys_key == encryption.read_text().strip()
    assert stored.intelligence_keys_key not in repr(stored)
    invalid_ca = tmp_path / "invalid-ca.pem"
    invalid_ca.write_text("not a PEM trust bundle")
    cfg.intelligence_ca_file = str(invalid_ca)
    with pytest.raises(ValueError, match="CA file"):
        cfg.validate()
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_ORIGIN", ORIGIN)
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_API_KEY", KEY)
    assert Connection.from_config(from_env()) == connection
    monkeypatch.delenv("OPENAIDR_INTELLIGENCE_ORIGIN")
    monkeypatch.delenv("OPENAIDR_INTELLIGENCE_API_KEY_FILE")
    with pytest.raises(ValueError, match="Replace legacy"):
        Connection.from_config(from_env())
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_ORIGIN", ORIGIN)
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_API_KEY_FILE", str(secret))
    monkeypatch.setenv("OPENAIDR_THREAT_INTEL_ORIGIN", "https://another.example.com")
    with pytest.raises(ValueError, match="Replace legacy"):
        Connection.from_config(from_env())
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_API_KEY", KEY)
    with pytest.raises(ValueError, match="only one"):
        from_env()


@pytest.mark.parametrize("changes", [
    {"intelligence_origin": ""}, {"intelligence_api_key": ""}, {"tenant_id": ""}, {"intelligence_keys_key": "invalid"},
    {"intelligence_origin": "http://localhost:8080"}, {"intelligence_origin": ORIGIN + "/"},
    {"intelligence_origin": "https://name:secret@intelligence.example.com"},
    {"intelligence_ca_file": "/missing/intelligence-ca.pem"},
    {"threat_intel_origin": ORIGIN}, {"threat_intel_origin": ORIGIN, "threat_intel_api_key": KEY + "x"},
    {"intelligence_origin": "", "intelligence_api_key": "", "intelligence_ca_file": "/missing/ca.pem"},
])
def test_incomplete_conflicting_or_insecure_connection_fails_startup(changes):
    values = {"intelligence_origin": ORIGIN, "intelligence_api_key": KEY, "tenant_id": TENANT, **changes}
    cfg = Config(database_url="unused", **values)
    cfg.set_services("ingest,detect")
    with pytest.raises(ValueError):
        cfg.validate()


def certificate(subject, key, issuer=None, issuer_key=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer.subject if issuer else name).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
               .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
               .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None), True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, issuer is None, issuer is None, False, False), True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), False))
    if issuer:
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(issuer_key or key, hashes.SHA256())


@pytest.fixture
def tls_service(tmp_path):
    authority_key, server_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    authority = certificate("Intelligence fixture CA", authority_key)
    paths = {name: tmp_path / name for name in ("ca.pem", "server.pem", "server.key", "wrong-ca.pem")}
    paths["ca.pem"].write_bytes(authority.public_bytes(serialization.Encoding.PEM))
    paths["server.pem"].write_bytes(certificate("localhost", server_key, authority, authority_key).public_bytes(serialization.Encoding.PEM))
    paths["server.key"].write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths["wrong-ca.pem"].write_bytes(certificate("Other fixture CA", ec.generate_private_key(ec.SECP256R1())).public_bytes(serialization.Encoding.PEM))
    database, token_file = tmp_path / "keys.sqlite3", tmp_path / "tenant.key"
    keys.initialize(database)
    key_id = keys.issue(database, TENANT, token_file)
    provider = Provider()
    app = create_service(ServiceConfig(str(database), "provider-fixture"),
                         transport=httpx.MockTransport(provider.handle), version="2026.10.26+1234567")
    received = []

    @app.middleware("http")
    async def observe(request, call_next):
        received.append(request.url.path)
        return await call_next(request)

    @app.post("/v1/redirect")
    async def redirect():
        return RedirectResponse("https://other.example.com/v1/receive", status_code=307)

    @app.post("/v1/oversized")
    async def oversized():
        return JSONResponse({"value": "a" * 1024})

    @app.post("/v1/slow")
    async def slow():
        await asyncio.sleep(0.1)
        return JSONResponse({})

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"https://localhost:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on", ws="none",
                            ssl_certfile=str(paths["server.pem"]), ssl_keyfile=str(paths["server.key"])))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        yield SimpleNamespace(origin=origin, token=token_file.read_text().strip(), paths=paths,
                              database=database, key_id=key_id, provider=provider, received=received)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


@pytest.mark.parametrize("prefix", ["INTELLIGENCE"])
def test_real_tls_authentication_scope_transport_bounds_and_revocation(tls_service, connection_environment, monkeypatch, prefix):
    service = tls_service
    ca_file = str(service.paths["ca.pem"])
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", ca_file)
    monkeypatch.setenv("OPENAIDR_" + prefix + "_ORIGIN", service.origin)
    monkeypatch.setenv("OPENAIDR_" + prefix + "_API_KEY", service.token)
    monkeypatch.setenv("OPENAIDR_INTELLIGENCE_CA_FILE", ca_file)
    connection = Connection.from_config(from_env())

    async def run():
        client = ThreatIntelClient.from_connection(connection)
        try:
            assert client.connection == connection
            assert (await client.assess(TENANT, [{"text": BAD}]))["status"] == "matched"
            assert (await client.packages([QUERY]))[0]["status"] == "complete"
            requests = len(service.received)
            assert (await client.assess(str(uuid4()), [{"text": BAD}]))["status"] == "unavailable"
            assert len(service.received) == requests
            for origin, key, ca in ((service.origin, service.token, ""),
                                    (service.origin, service.token, str(service.paths["wrong-ca.pem"])),
                                    (service.origin.replace("localhost", "127.0.0.1"), service.token, ca_file),
                                    (service.origin, KEY, ca_file)):
                rejected = ThreatIntelClient(origin, key, TENANT, ca_file=ca)
                try:
                    assert (await rejected.assess(TENANT, [{"text": BAD}]))["status"] == "unavailable"
                    with pytest.raises((osv.Unavailable, httpx.HTTPError)):
                        await rejected.packages([QUERY])
                finally:
                    await rejected.aclose()
            transport = IntelligenceClient.from_connection(connection)
            try:
                for path in ("https://other.example.com/v1/receive", "//other.example.com/v1/receive"):
                    with pytest.raises(Unavailable, match="path"):
                        await transport.request(path, {}, 1024, 1)
                for path, limit in (("/v1/redirect", 1024), ("/v1/oversized", 128)):
                    with pytest.raises(Unavailable):
                        await transport.request(path, {}, limit, 1)
                with pytest.raises(TimeoutError):
                    await transport.request("/v1/slow", {}, 1024, 0.02)
            finally:
                await transport.aclose()
            assert keys.revoke(service.database, service.key_id)
            assert (await client.assess(TENANT, [{"text": BAD}]))["status"] == "unavailable"
        finally:
            await client.aclose()

    asyncio.run(run())
    assert "/v1/receive" not in service.received


def test_tenant_and_scanner_use_the_selected_private_tls_service(db, tls_service, monkeypatch, tmp_path):
    own = tenant(db)
    _, sensor_token, _ = sensor(db, own["id"])
    hook_policy.save_settings(db, own["id"], {"mode": "enforce", "version": 0}, {})
    db.save_policy(own["id"], [])
    key_file = tmp_path / "backend.key"
    key_id = keys.issue(tls_service.database, own["id"], key_file)
    cfg = Config(database_url=db.url, tenant_id=own["id"], intelligence_origin=tls_service.origin,
                 intelligence_api_key=key_file.read_text().strip(), intelligence_ca_file=str(tls_service.paths["ca.pem"]),
                 cost_processing=False)
    cfg.set_services("ingest")
    monkeypatch.setattr(provider_links, "WebRiskClient", lambda *args, **kwargs: pytest.fail("Direct provider bypass"))
    from fastapi.testclient import TestClient

    with TestClient(create_app(cfg, db)) as backend:
        body = payload()
        body["actions"][0]["text"] = BAD
        result = backend.post("/ingest/v1/hook-checks", headers={"Authorization": "Bearer " + sensor_token}, json=body)
        assert result.status_code == 200 and result.json()["returned_decision"] == "deny"
        connection = Connection.from_config(cfg)
        with skill_intel_proxy.provider(connection) as bridge:
            assert connection.api_key not in json.dumps(bridge.environment)
            with httpx.Client(base_url=bridge.environment["OPENAIDR_SKILL_INTEL_ORIGIN"], trust_env=False) as scanner:
                request = {"packages": [{"ecosystem": "npm", "name": "example", "version": "1.0.0"}], "timeout": 5}
                headers = {"Authorization": "Bearer " + bridge.environment["OPENAIDR_SKILL_INTEL_TOKEN"]}
                result = scanner.post("/v1/packages/check", headers=headers, json=request)
                assert result.status_code == 200 and result.json()["results"][0]["status"] == "complete"
                assert keys.revoke(tls_service.database, key_id)
                result = scanner.post("/v1/packages/check", headers=headers, json=request)
                assert result.json()["results"][0]["status"] == "unavailable"
        body = payload()
        body["actions"][0]["text"] = BAD
        result = backend.post("/ingest/v1/hook-checks", headers={"Authorization": "Bearer " + sensor_token}, json=body)
        assert result.status_code == 200 and result.json()["returned_decision"] == "allow"
        assert result.json()["assessment"]["links"]["status"] == "unavailable"


def test_sync_connection_keeps_tls_bounds_and_thread_pool_calls(tls_service):
    from concurrent.futures import ThreadPoolExecutor

    connection = Connection(tls_service.origin, tls_service.token, TENANT,
                            str(tls_service.paths["ca.pem"]))
    client = SyncIntelligenceClient.from_connection(connection)
    try:
        assert client.connection == connection
        assert client.connection.fingerprint() == connection.fingerprint()
        assert connection.fingerprint() != Connection(connection.origin, KEY, TENANT,
                                                       connection.ca_file).fingerprint()
        with ThreadPoolExecutor(max_workers=2) as workers:
            responses = list(workers.map(lambda _: client.request("/v1/oversized", {}, 2048, 2), range(4)))
        assert responses == [{"value": "a" * 1024}] * 4
        for path, limit in (("/v1/redirect", 2048), ("/v1/oversized", 100),
                            ("https://other.example.com/v1/receive", 2048)):
            with pytest.raises(Unavailable):
                client.request(path, {}, limit, 2)
        with pytest.raises(TimeoutError):
            client.request("/v1/slow", {}, 1024, 0.02)
        assert client.request("/v1/oversized", {}, 2048, 2)["value"]
    finally:
        client.close()
    client.close()
    with pytest.raises(Unavailable):
        client.request("/v1/oversized", {}, 2048, 2)
    assert "/v1/receive" not in tls_service.received


def test_sync_connection_closes_an_inflight_request():
    from concurrent.futures import CancelledError, ThreadPoolExecutor

    entered = threading.Event()

    async def provider(request):
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("A cancelled request cannot complete")

    client = SyncIntelligenceClient(ORIGIN, KEY, TENANT, transport=httpx.MockTransport(provider))
    with ThreadPoolExecutor(max_workers=1) as worker:
        request = worker.submit(client.request, "/v1/wait", {}, 1024, 5)
        assert entered.wait(2)
        client.close()
        with pytest.raises(CancelledError):
            request.result(timeout=2)


def test_settings_capabilities_authenticate_the_selected_tls_service_without_model_requests(db, tls_service, tmp_path):
    from fastapi.testclient import TestClient

    service, own = tls_service, tenant(db)
    users = {role: db.create_user(own["id"], role + "@example.test", role, "hash", role)
             for role in ("owner", "viewer")}
    headers = {role: {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], own["id"]),
                       auth.CSRF_HEADER: "1"} for role, user in users.items()}
    token_file = tmp_path / "settings.key"
    key_id = keys.issue(service.database, own["id"], token_file)
    cfg = Config(database_url=db.url, public_url="http://testserver", tenant_id=own["id"],
                 intelligence_origin=service.origin, intelligence_api_key=token_file.read_text().strip(),
                 intelligence_ca_file=str(service.paths["ca.pem"]), cost_processing=False,
                 openai_api_key="retained-direct-openai-key", )
    cfg.set_services("api")
    path = "/api/v1/settings/intelligence/check"
    with closing(TestClient(create_app(cfg, db))) as client:
        assert client.post(path, json={}, headers={auth.CSRF_HEADER: "1"}).status_code == 401
        assert client.post(path, json={}, headers=headers["viewer"]).status_code == 403
        assert client.post(path, json={}, headers={"Cookie": headers["owner"]["Cookie"]}).status_code == 403
        assert client.post(path, json={"origin": "https://other.example.com"}, headers=headers["owner"]).status_code == 400
        assert not service.received
        result = client.post(path, json={}, headers=headers["owner"])
        assert result.status_code == 200 and result.headers["cache-control"] == "no-store"
        value = result.json()
        assert value["tenant_id"] == own["id"] and value["origin"] == service.origin
        assert value["build"] == "2026.10.26+1234567" and value["checked_at"]
        assert value["provider_access"] == value["investigation_worker"] == "not_checked"
        assert value["capabilities"]["assistant"] == "provider_unconfigured"
        assert value["capabilities"]["package_vulnerabilities"] == "configured"
        assert all(key not in result.text for key in (cfg.intelligence_api_key, cfg.openai_api_key))
        keys.revoke(service.database, key_id)
        unavailable = client.post(path, json={}, headers=headers["owner"])
        assert unavailable.status_code == 400 and "rejected this key" in unavailable.text
        assert client.get("/api/v1/settings/model-keys", headers=headers["owner"]).json()["routing"]["mode"] == "intelligence"
    # A rejected key also gets one tenant-aware discovery attempt before failing.
    assert service.received == ["/v1/capabilities"] * 3
    for changes, status, reached in (
        ({"intelligence_api_key": service.token}, 400, True),  # A valid credential for another tenant.
        ({"intelligence_ca_file": str(service.paths["wrong-ca.pem"])}, 503, False),
        ({"tenant_id": TENANT}, 403, False),
        ({"intelligence_origin": "", "intelligence_api_key": "", "intelligence_ca_file": ""}, 409, False),
    ):
        previous = len(service.received)
        with closing(TestClient(create_app(replace(cfg, **changes), db))) as client:
            result = client.post(path, json={}, headers=headers["owner"])
        assert result.status_code == status
        assert len(service.received) == previous + int(reached)
        assert service.token not in result.text
    assert not service.provider.requests
    assert db.scalar("SELECT count(*) FROM model_usage WHERE tenant_id=$1", own["id"]) == 0


def test_canonical_connection_preserves_persisted_fingerprint():
    import hashlib
    import json
    connection = Connection("https://intelligence.example", "oati_" + "a" * 32 + "." + "b" * 43, TENANT)
    expected = hashlib.sha256(json.dumps([
        connection.origin, connection.tenant_id, connection.api_key, True,
        hashlib.sha256(b"default public trust").hexdigest(),
    ]).encode()).hexdigest()
    assert connection.fingerprint() == expected


@pytest.mark.parametrize("path,allowed", [
    ("/v1/investigations", True), ("/v1/investigations/runtime", True),
    ("/v1/investigations/019a0000-0000-7000-8000-000000000001/exchange", True),
    ("/v2/investigations", False), ("/v2/investigations/runtime", False),
    ("/v2/other", False), ("https://other.example.com/v1/investigations", False),
    ("//other.example.com/v1/investigations", False),
    ("/v1/investigations?origin=other", False), ("/v1/investigations#other", False),
])
def test_transport_rejects_retired_protocols_and_foreign_origins(path, allowed):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    client = SyncIntelligenceClient(ORIGIN, KEY, TENANT, transport=httpx.MockTransport(handle))
    try:
        if allowed:
            assert client.request(path, {}, 1024, 1) == {"ok": True}
            assert seen[0].url.host == "intelligence.example.com"
        else:
            with pytest.raises(Unavailable, match="path"):
                client.request(path, {}, 1024, 1)
            assert not seen
    finally:
        client.close()
