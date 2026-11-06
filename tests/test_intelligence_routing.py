"""Production routing and credential isolation through PostgreSQL and the SDK."""

import json
from dataclasses import replace
from uuid import UUID, uuid4

import certifi
from cryptography.fernet import Fernet
import httpx
import psycopg
import pytest

from openaidr_api_client.contracts.capabilities import CAPABILITIES
from openaidr_api_client.client import Connection
from openaidr.server import intelligence, model_keys
from openaidr.server.config import Config
from openaidr.server.httpx import APIError
from test_store import db as db, tenant


PRODUCTION = "https://api.opensecura.ai"
RETIRED = "https://retired.example.test"


@pytest.fixture
def workspace(db, intelligence_key, monkeypatch):
    tid = tenant(db)["id"]
    cfg = Config(database_url=db.url, tenant_id=tid, intelligence_origin=PRODUCTION,
                 intelligence_api_key=intelligence_key,
                 intelligence_keys_key=Fernet.generate_key().decode())
    requests = []

    async def receive(transport, request):
        requests.append(request)
        assert str(request.url) == PRODUCTION + "/v1/capabilities"
        return httpx.Response(200, json={"tenant_id": tid, "build": "2026.11.5+be4f2ee",
            "capabilities": dict.fromkeys(CAPABILITIES, "configured"),
            "provider_access": "not_checked", "investigation_worker": "not_checked"})

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", receive)
    return tid, cfg, requests


def test_production_settings_verify_and_replace_only_the_production_key(db, workspace):
    tid, cfg, requests = workspace
    assert intelligence.ORIGINS == (PRODUCTION,)
    routing = model_keys.read(db, tid, cfg)["routing"]
    assert routing["origin"] == PRODUCTION
    assert routing["environments"] == [{"origin": PRODUCTION, "label": "Production",
                                        "saved_key": False, "credential_configured": True}]
    assert model_keys.check_capabilities(tid, {}, cfg, db)["origin"] == PRODUCTION
    replacement = cfg.intelligence_api_key[:-1] + "c"
    result = model_keys.save_environment_key(db, tid,
        {"origin": PRODUCTION, "api_key": replacement, "version": 0, "activate": True}, {}, cfg)
    assert result["routing"]["environments"][0]["saved_key"] is True
    assert intelligence.selected_connection(cfg, db).api_key == replacement
    assert [request.headers["authorization"] for request in requests] == [
        "Bearer " + cfg.intelligence_api_key, "Bearer " + replacement]
    saved = db.scalar("SELECT encrypted_api_key FROM tenant_intelligence_keys WHERE tenant_id=$1", tid)
    assert replacement not in saved and replacement not in json.dumps(result, default=str)
    for origin in (RETIRED, "https://untrusted.example.test"):
        before = len(requests)
        with pytest.raises(APIError):
            model_keys.save_connection(db, tid, {"origin": origin, "version": 1}, {}, cfg)
        with pytest.raises(APIError):
            model_keys.save_environment_key(db, tid,
                {"origin": origin, "api_key": replacement, "version": 1}, {}, cfg)
        assert len(requests) == before
        assert intelligence.connection_for_origin(cfg, db, origin) is None
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE tenant_intelligence_selection SET origin=$2 WHERE tenant_id=$1", tid, RETIRED)
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE tenant_intelligence_keys SET origin=$2 WHERE tenant_id=$1", tid, RETIRED)


def test_retired_saved_selection_requires_explicit_production_activation(db, workspace, intelligence_environments, monkeypatch):
    from openaidr.server import skill_llm

    tid, cfg, requests = workspace
    # Simulate an upgraded database whose existing constraints and rows remain.
    retired = intelligence_environments[0]
    for module in (intelligence, model_keys, skill_llm):
        monkeypatch.setattr(module, "ORIGINS", (PRODUCTION,))
    retired_key = cfg.intelligence_api_key[:-1] + "c"
    encrypted = intelligence.cipher(cfg).encrypt(json.dumps([tid, retired, retired_key]).encode()).decode()
    db.execute("INSERT INTO tenant_intelligence_selection(tenant_id,origin,version) VALUES($1,$2,7)", tid, retired)
    db.execute("INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,$3)",
               tid, retired, encrypted)
    cfg.intelligence_origin = retired
    assert intelligence.selected_connection(cfg, db).api_key == retired_key
    assert "environments" not in model_keys.read(db, tid, cfg)["routing"]
    cfg.intelligence_origin = PRODUCTION
    assert intelligence.selected_connection(cfg, db) is None
    assert model_keys.read(db, tid, cfg)["routing"]["credential_configured"] is False
    with pytest.raises(APIError):
        model_keys.check_capabilities(tid, {}, cfg, db)
    assert requests == []
    result = model_keys.save_connection(db, tid, {"origin": PRODUCTION, "version": 7}, {}, cfg)
    assert result["routing"]["origin"] == PRODUCTION
    assert intelligence.selected_connection(cfg, db).api_key == cfg.intelligence_api_key
    assert len(requests) == 1
    assert db.scalar("SELECT encrypted_api_key FROM tenant_intelligence_keys WHERE tenant_id=$1 AND origin=$2",
                     tid, retired) == encrypted
    cfg.intelligence_origin = "https://configured.example.test"
    assert intelligence.selected_connection(cfg, db) is None
    db.execute("DELETE FROM tenant_intelligence_selection WHERE tenant_id=$1", tid)
    assert intelligence.selected_connection(cfg, db).origin == cfg.intelligence_origin


@pytest.mark.parametrize("saved_selection", [False, True])
def test_configured_endpoint_only_manages_an_existing_production_selection(db, workspace, saved_selection):
    tid, cfg, requests = workspace
    cfg.intelligence_origin = RETIRED
    replacement = cfg.intelligence_api_key[:-1] + "c"
    if saved_selection:
        encrypted = intelligence.cipher(cfg).encrypt(json.dumps([tid, PRODUCTION, replacement]).encode()).decode()
        db.execute("INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,$3)",
                   tid, PRODUCTION, encrypted)
        db.execute("INSERT INTO tenant_intelligence_selection(tenant_id,origin) VALUES($1,$2)", tid, PRODUCTION)
        selected = intelligence.selected_connection(cfg, db)
        assert (selected.origin, selected.api_key) == (PRODUCTION, replacement)
        assert model_keys.check_capabilities(tid, {}, cfg, db)["origin"] == PRODUCTION
        db.execute("DELETE FROM tenant_intelligence_keys WHERE tenant_id=$1", tid)
        assert intelligence.selected_connection(cfg, db) is None
        with pytest.raises(APIError):
            model_keys.check_capabilities(tid, {}, cfg, db)
        assert len(requests) == 1
    else:
        assert intelligence.selected_connection(cfg, db).origin == RETIRED
        assert "environments" not in model_keys.read(db, tid, cfg)["routing"]
        assert model_keys.read(db, tid, cfg)["routing"]["credential_management"] is False
        with pytest.raises(APIError):
            model_keys.save_connection(db, tid, {"origin": PRODUCTION, "version": 0}, {}, cfg)
        for activate in (False, True):
            with pytest.raises(APIError):
                model_keys.save_environment_key(db, tid,
                    {"origin": PRODUCTION, "api_key": replacement, "version": 0, "activate": activate}, {}, cfg)
        assert intelligence.selected_connection(cfg, db).origin == RETIRED
        assert requests == []
        return
    result = model_keys.save_environment_key(db, tid,
        {"origin": PRODUCTION, "api_key": replacement, "version": int(saved_selection), "activate": True}, {}, cfg)
    assert result["routing"]["origin"] == PRODUCTION
    assert all(request.headers["authorization"] == "Bearer " + replacement for request in requests)
    assert intelligence.selected_connection(cfg, db).api_key == replacement
    assert cfg.intelligence_origin == RETIRED
    assert intelligence.connection_for_origin(cfg, db, RETIRED).api_key == cfg.intelligence_api_key

    from openaidr.server.skill_worker import job_connection

    configured = Connection.from_config(cfg)
    worker = job_connection({"intelligence_origin": PRODUCTION, "intelligence_key": replacement}, configured)
    assert (worker.origin, worker.api_key) == (PRODUCTION, replacement)
    assert job_connection({"intelligence_origin": RETIRED, "intelligence_key": configured.api_key}, configured) == configured
    for job in ({"intelligence_origin": PRODUCTION},
                {"intelligence_origin": "https://untrusted.example.test", "intelligence_key": replacement}):
        with pytest.raises(ValueError):
            job_connection(job, configured)
    with pytest.raises(ValueError):
        job_connection({"intelligence_origin": PRODUCTION, "intelligence_key": replacement},
                       replace(configured, ca_file=certifi.where()))


@pytest.mark.parametrize("original_origin", [RETIRED, PRODUCTION])
def test_active_scan_lease_keeps_its_original_connection(db, workspace, original_origin):
    from openaidr.server import skill_llm

    tid, cfg, _ = workspace
    replacement = cfg.intelligence_api_key[:-1] + "c"
    model_keys.save_environment_key(db, tid,
        {"origin": PRODUCTION, "api_key": replacement, "version": 0, "activate": True}, {}, cfg)
    cfg.intelligence_origin = RETIRED
    original = intelligence.connection_for_origin(cfg, db, original_origin)
    data = {"sha256": "a" * 64, "lease_id": str(uuid4())}
    db.execute("""INSERT INTO skill_bundles(tenant_id,sha256,manifest,content_bytes,status,lease_id,lease_until,
        model_connection_binding,worker_protocol) VALUES($1,$2,'{}',0,'running',$3,now()+interval '1 minute',$4,$5)""",
        tid, data["sha256"], data["lease_id"], skill_llm.connection_binding(original), skill_llm.LEGACY_PROTOCOL)
    assert skill_llm.lease_connection(db, tid, cfg, data) == original
    db.execute("UPDATE skill_bundles SET model_connection_binding=$1",
               skill_llm.connection_binding(replace(original, origin="https://untrusted.example.test")))
    with pytest.raises(APIError):
        skill_llm.lease_connection(db, tid, cfg, data)


@pytest.mark.parametrize("restriction", ["private_ca", "free_installation"])
def test_private_trust_and_free_identity_do_not_enable_environment_switching(db, workspace, restriction):
    tid, cfg, requests = workspace
    if restriction == "private_ca":
        cfg.intelligence_ca_file = certifi.where()
    else:
        identity, cfg.free_secret = cfg.intelligence_api_key.split("_", 1)[1].split(".")
        cfg.free_installation_id = str(UUID(identity))
    assert "environments" not in model_keys.read(db, tid, cfg)["routing"]
    with pytest.raises(APIError):
        model_keys.save_environment_key(db, tid,
            {"origin": PRODUCTION, "api_key": cfg.intelligence_api_key, "version": 0}, {}, cfg)
    assert requests == []
