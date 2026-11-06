"""Local package dispatch, durable receipts, and account boundaries over HTTP."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from openaidr_api_client.client import Connection
from openaidr_api_client.contracts.capabilities import CAPABILITIES

from openaidr.sensor import free_enrollment, posture_assessments as assessments
from openaidr.sensor.config import Config
from openaidr.sensor.inventory_service import InventoryService
from openaidr.sensor.posture_store import Store
from openaidr.sensor.usage import identity
from test_hooks_setup import sensor_config


def configured(tmp_path, monkeypatch, intelligence_key, mode="api_key", count=1):
    cfg = sensor_config(tmp_path)
    cfg.update(connection_mode=mode, server_url=free_enrollment.ORIGIN, sensor_token=intelligence_key,
               tenant_id="00000000-0000-4000-8000-000000000001")
    cfg["posture"] = {"automatic": True, "scope": identity(cfg)}
    cfg.save()
    bound = Connection(cfg["server_url"], intelligence_key, cfg["tenant_id"])
    monkeypatch.setattr(free_enrollment, "prepare", lambda config: SimpleNamespace(connection=bound))
    inventory = InventoryService(cfg, None, components=True)
    rows = [dict(kind="package", key=f"package-{i}", name=f"package-{i}", ecosystem="npm", identifier=f"package-{i}", version="1.0.0",
                 path="/private/project/secret-lock.json", metadata={"token": "never-send"}) for i in range(count)]
    inventory.path.parent.mkdir(parents=True, exist_ok=True)
    inventory.path.write_text(json.dumps(dict(identity=inventory.identity, snapshot=dict(schema_version=1,
        collected_at=datetime.now(timezone.utc).isoformat(), roots=[dict(source="osquery-npm-packages", root="/private/project",
        scope="project", status="ok", components=[*rows, *rows, dict(kind="mcp_server", identifier="private")])]))))
    return cfg


def service(cfg, calls):
    def respond(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer " + cfg["sensor_token"]
        now = datetime.now(timezone.utc)
        if request.url.path == "/v1/free/usage":
            return httpx.Response(200, json=dict(tenant_id=cfg["tenant_id"], plan="free", usage=dict(
                status="active", allowance="200", used="0", reserved="0", available="200",
                starts_at=(now-timedelta(days=1)).isoformat(), resets_at=(now+timedelta(days=1)).isoformat(),
                checked_at=now.isoformat())))
        if request.url.path == "/v1/credits":
            return httpx.Response(200, json=dict(schema_version=1, tenant_id=cfg["tenant_id"], status="active",
                rate_version="test.1", credits_per_usd="100", since=(now-timedelta(days=1)).isoformat(),
                until=now.isoformat(), bucket_seconds=3600, balance=dict(available="200", reserved="0"),
                summary=dict(credits_charged="0", operations=0, pending_operations=0, unrated_operations=0),
                by_service=[], series=[]))
        if request.url.path == "/v1/capabilities":
            return httpx.Response(200, json=dict(tenant_id=cfg["tenant_id"], build="test",
                capabilities={key: "configured" for key in CAPABILITIES}, provider_access="not_checked",
                investigation_worker="not_checked"))
        assert request.url.path == "/v1/services/packages/check" and request.method == "POST"
        payload = json.loads(request.content)
        assert set(payload) == {"packages"}
        assert all(set(item) == {"ecosystem", "name", "version"} for item in payload["packages"])
        checked = now-timedelta(seconds=1)
        return httpx.Response(200, json=dict(profile="package-vulnerabilities.1", results=[dict(
            query=dict(package=dict(ecosystem=row["ecosystem"], name=row["name"]), version=row["version"]),
            status="complete", findings=[], checked_at=checked.isoformat(),
            expires_at=(checked+timedelta(days=1)).isoformat(), reason="") for row in payload["packages"]],
            billing=dict(request_id=request.headers["Idempotency-Key"], service="package_vulnerabilities",
                state="settled", credits_reserved="2", credits_charged="2", rate_version="test.1")))
    return respond


def checks(calls):
    return [request for request in calls if request.url.path == "/v1/services/packages/check"]


def test_default_disabled_and_stale_consent_never_call_cloud(tmp_path, monkeypatch, intelligence_key):
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    calls = []
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(service(cfg, calls)))
    for options in ({}, {"automatic": False, "scope": identity(cfg)}, {"automatic": True, "scope": "old-account"}):
        cfg["posture"] = options
        cfg.save()
        assert asyncio.run(worker.once()) is False
    assert calls == []
    assert not (Path(cfg["data_dir"])/"posture-assessments.sqlite3").exists()


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_packages_deduplicate_batch_and_reuse_paid_results_for_24_hours(tmp_path, monkeypatch, intelligence_key, mode):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, mode, count=27)
    calls = []
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(service(cfg, calls)))
    assert asyncio.run(worker.once()) is True
    assert asyncio.run(worker.once()) is True
    assert [len(json.loads(request.content)["packages"]) for request in checks(calls)] == [25, 2]
    assert all("private" not in request.content.decode() and "never-send" not in request.content.decode() for request in calls)
    records = Store(cfg).records()
    assert len(records) == 27 and {row["state"] for row in records.values()} == {"complete"}
    for row in records.values():
        report = row["report"]
        assert datetime.fromisoformat(report["expires_at"])-datetime.fromisoformat(report["checked_at"]) == timedelta(days=1)
    assert Store(cfg).summary() == dict(credits_charged="4", credits_reserved="0", unknown_attempts=0)
    assert len({request.headers["Idempotency-Key"] for request in checks(calls)}) == 2
    later = assessments.time.time()+23*3600
    monkeypatch.setattr(assessments.time, "time", lambda: later)
    assert asyncio.run(worker.once()) is False
    assert len(checks(calls)) == 2


@pytest.mark.parametrize("failure", ["credits", "lost_response"])
def test_rejected_dispatch_retries_but_unknown_charge_is_held(tmp_path, monkeypatch, intelligence_key, failure):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=27 if failure == "credits" else 1)
    calls = []
    normal = service(cfg, calls)
    def remote(request):
        if request.url.path != "/v1/services/packages/check":
            return normal(request)
        calls.append(request)
        if failure == "credits":
            return httpx.Response(402, json={"error": "credits_exhausted"})
        raise httpx.ReadTimeout("response lost", request=request)
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(remote))
    assert asyncio.run(worker.once()) is False
    record = next(iter(Store(cfg).records().values()))
    assert record["state"] == ("retry" if failure == "credits" else "unknown")
    assert assessments.status(cfg)["state"] == ("exhausted" if failure == "credits" else "unavailable")
    before = len(calls)
    assert asyncio.run(worker.once()) is False and len(checks(calls)) == 1
    if failure == "credits":
        assert len(calls) == before
    later = assessments.time.time()+2*86400
    monkeypatch.setattr(assessments.time, "time", lambda: later)
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(normal))
    assert asyncio.run(worker.once()) is (failure == "credits")
    assert len(checks(calls)) == (2 if failure == "credits" else 1)
    assert Store(cfg).summary()["unknown_attempts"] == (0 if failure == "credits" else 1)


def test_zero_available_balance_never_dispatches_even_with_active_account(tmp_path, monkeypatch, intelligence_key):
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    calls = []
    normal = service(cfg, calls)
    def remote(request):
        response = normal(request)
        value = response.json()
        value["balance"]["available"] = "0"
        return httpx.Response(200, json=value)
    assert not asyncio.run(assessments.Worker(cfg, transport=httpx.MockTransport(remote)).once())
    assert len(calls) == 1 and checks(calls) == []
    assert assessments.status(cfg)["state"] == "exhausted"


def test_confirmed_released_failure_can_retry_and_summary_only_reads_retained_evidence(tmp_path, monkeypatch, intelligence_key):
    from openaidr.sensor.local_posture import read
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    calls = []
    normal = service(cfg, calls)
    def released(request):
        response = normal(request)
        if request.url.path == "/v1/services/packages/check":
            value = response.json()
            value["billing"].update(state="released", credits_charged="0")
            value["results"][0].update(status="unavailable", checked_at=None, expires_at=None,
                                      reason="Service assessment unavailable")
            return httpx.Response(200, json=value)
        return response
    assert not asyncio.run(assessments.Worker(cfg, transport=httpx.MockTransport(released)).once())
    record, = Store(cfg).records().values()
    assert record["state"] == "retry" and record["billing_state"] == "released"
    later = assessments.time.time()+901
    monkeypatch.setattr(assessments.time, "time", lambda: later)
    assert asyncio.run(assessments.Worker(cfg, transport=httpx.MockTransport(normal)).once())
    before = len(calls)
    value = read(cfg)
    assert len(calls) == before and value["groups"]["components"]["items"][0]["assessment_status"] == "complete"
    assert value["assessments"]["usage"]["credits_charged"] == "2"
    assessments.configure(cfg, False, identity(cfg))
    assert read(Config.load(cfg.path))["groups"]["components"]["items"][0]["assessment_status"] == "complete"
    with pytest.raises(ValueError, match="connection changed"):
        assessments.configure(cfg, True, "other-account")


def test_unsettled_expired_result_cannot_block_new_packages(tmp_path, monkeypatch, intelligence_key):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=2)
    key = sorted(assessments.packages(cfg))[0]
    store = Store(cfg)
    request = store.claim("package_vulnerabilities", [key])
    store.complete(request, {key: dict(checked_at="2020-01-01T00:00:00Z", expires_at="2020-01-02T00:00:00Z", findings=[])})
    calls = []
    assert asyncio.run(assessments.Worker(cfg, transport=httpx.MockTransport(service(cfg, calls))).once())
    assert len(checks(calls)) == 1 and len(json.loads(checks(calls)[0].content)["packages"]) == 1
    assert Store(cfg).summary()["unknown_attempts"] == 1


@pytest.mark.parametrize("change", ["pause", "identity", "credential"])
def test_connection_or_pause_change_before_dispatch_prevents_charge(tmp_path, monkeypatch, intelligence_key, change):
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    calls, paused = [], []
    normal = service(cfg, calls)
    def remote(request):
        response = normal(request)
        if request.url.path == "/v1/capabilities":
            if change == "pause":
                paused.append(True)
            else:
                latest = Config.load(cfg.path)
                latest["sensor_id" if change == "identity" else "sensor_token"] += "changed"
                latest.save()
        return response
    assert asyncio.run(assessments.Worker(cfg, paused=lambda: bool(paused), transport=httpx.MockTransport(remote)).once()) is False
    assert checks(calls) == [] and Store(cfg).records() == {}


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_unavailable_billing_prevents_assessment(tmp_path, monkeypatch, intelligence_key, mode):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, mode)
    calls = []
    def remote(request):
        calls.append(request)
        return httpx.Response(503, json={"error": "unavailable"})
    assert asyncio.run(assessments.Worker(cfg, transport=httpx.MockTransport(remote)).once()) is False
    assert len(calls) == 1 and checks(calls) == []
    assert assessments.status(cfg)["state"] == "unavailable"


@pytest.mark.parametrize("invalid", ["profile", "query", "expiry", "receipt"])
def test_invalid_result_preserves_known_charge_and_never_retries(tmp_path, monkeypatch, intelligence_key, invalid):
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    calls = []
    normal = service(cfg, calls)
    def remote(request):
        response = normal(request)
        if request.url.path == "/v1/services/packages/check":
            value = response.json()
            if invalid == "profile":
                value["profile"] = "other.1"
            elif invalid == "query":
                value["results"][0]["query"]["package"]["name"] = "other-package"
            elif invalid == "expiry":
                value["results"][0]["expires_at"] = value["results"][0]["checked_at"]
            else:
                value["billing"]["request_id"] = "00000000-0000-4000-8000-000000000002"
            return httpx.Response(200, json=value)
        return response
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(remote))
    assert asyncio.run(worker.once()) is False
    record, = Store(cfg).records().values()
    assert record["state"] == "unknown" and record["report"] is None
    assert Store(cfg).summary() == dict(credits_charged="0" if invalid == "receipt" else "2", credits_reserved="0", unknown_attempts=1)
    assert asyncio.run(worker.once()) is False and len(checks(calls)) == 1
