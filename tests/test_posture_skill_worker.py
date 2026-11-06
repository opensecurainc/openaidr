"""Automatic skill work uses real captures, durable receipts, and read-only views."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import threading

import httpx
import pytest

from openaidr.sensor import desktop_posture, posture_assessments as assessments, posture_skills as skills
from openaidr.sensor.config import Config
from openaidr.sensor.inventory_service import InventoryService
from openaidr.sensor.posture_store import Store
from openaidr.sensor.usage import identity
from test_posture_assessments import configured, service
from test_posture_skills import inventory, response

ENDPOINT = "/v1/services/skills/assess-bundle"


def skill_calls(calls):
    return [request for request in calls if request.url.path == ENDPOINT]


def remote(cfg, calls, findings=None):
    other = service(cfg, calls)
    def reply(request):
        if request.url.path != ENDPOINT:
            return other(request)
        calls.append(request)
        assert request.headers["authorization"] == "Bearer " + cfg["sensor_token"]
        task = json.loads(request.content)
        assert all(not row["path"].startswith("/") for row in task["files"])
        return httpx.Response(200, json=response(task, request.headers["idempotency-key"], findings))
    return reply


@pytest.mark.parametrize("unavailable, capability_state", [
    (None, None),
    ("package_vulnerabilities", "runtime_unavailable"),
    ("skill_assessment", "runtime_unavailable"),
    ("package_vulnerabilities", "provider_unconfigured"),
    ("skill_assessment", "provider_unconfigured"),
])
def test_unavailable_capability_is_reported_without_blocking_other_work(tmp_path, monkeypatch, intelligence_key,
                                                                       unavailable, capability_state):
    cfg = configured(tmp_path, monkeypatch, intelligence_key)
    cache = InventoryService(cfg, None, components=True).path
    packages = json.loads(cache.read_text())["snapshot"]["roots"]
    inventory(tmp_path, cfg=cfg)
    snapshot = json.loads(cache.read_text())
    snapshot["snapshot"]["roots"].extend(packages)
    cache.write_text(json.dumps(snapshot))
    calls, waits = [], []
    async def wait(delay):
        waits.append(delay)
    monkeypatch.setattr(assessments.asyncio, "sleep", wait)
    normal = remote(cfg, calls)
    def reply(request):
        value = normal(request)
        if unavailable and request.url.path == "/v1/capabilities":
            data = value.json()
            data["capabilities"][unavailable] = capability_state
            return httpx.Response(200, json=data)
        return value
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(reply))
    for _ in range(1 if unavailable else 2):
        assert asyncio.run(worker.once()) is True
    assert waits == []
    for _ in range(2):
        assert asyncio.run(worker.once()) is False
        assert assessments.status(cfg)["state"] == ("unavailable" if unavailable else "idle")
    expected = {"package_vulnerabilities": "/v1/services/packages/check", "skill_assessment": ENDPOINT}
    assert [call.url.path for call in calls if call.method == "POST"] == [
        path for name, path in expected.items() if name != unavailable]
    assert Store(cfg).summary()["credits_charged"] == (
        "3" if unavailable is None else "1" if unavailable == "package_vulnerabilities" else "2")
    assert waits == ([2]*6 if capability_state == "runtime_unavailable" else [])


@pytest.mark.parametrize("service_name", ["package_vulnerabilities", "skill_assessment"])
@pytest.mark.parametrize("outcome", ["ready", "unavailable", "pause", "identity", "stop", "foreign_tenant"])
def test_cold_runtime_rechecks_are_bounded_and_keep_dispatch_authorized(tmp_path, monkeypatch, intelligence_key,
                                                                      service_name, outcome):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=1 if service_name == "package_vulnerabilities" else 0)
    if service_name == "skill_assessment":
        inventory(tmp_path, cfg=cfg)
    calls, waits, probes = [], [], []
    stop = threading.Event()
    normal = remote(cfg, calls)
    def reply(request):
        value = normal(request)
        if request.url.path == "/v1/capabilities":
            probes.append(request)
            data = value.json()
            if outcome != "ready" or len(probes) < 3:
                data["capabilities"][service_name] = "runtime_unavailable"
            if outcome == "foreign_tenant" and len(probes) == 2:
                data["tenant_id"] = "00000000-0000-4000-8000-000000000002"
            return httpx.Response(200, json=data)
        return value
    async def wait(delay):
        waits.append(delay)
        if outcome == "pause":
            assessments.configure(cfg, False, identity(cfg))
        elif outcome == "identity":
            latest = Config.load(cfg.path)
            latest["sensor_id"] = "changed-during-warmup"
            latest.save()
        elif outcome == "stop":
            stop.set()
    monkeypatch.setattr(assessments.asyncio, "sleep", wait)
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(reply))
    assert asyncio.run(worker.once(stop)) is (outcome == "ready")
    expected = 3 if outcome == "ready" else 4 if outcome == "unavailable" else 2 if outcome == "foreign_tenant" else 1
    assert len(probes) == expected
    assert waits == [2]*(expected-1 if outcome in ("ready", "unavailable", "foreign_tenant") else 1)
    assert len([call for call in calls if call.method == "POST"]) == (1 if outcome == "ready" else 0)
    if outcome in ("unavailable", "foreign_tenant"):
        assert assessments.status(cfg)["state"] == "unavailable"
    if outcome != "ready":
        assert Store(cfg).records() == {}


@pytest.mark.parametrize("mode", ["free", "api_key"])
def test_all_skill_files_are_assessed_once_without_persisted_request_content(tmp_path, monkeypatch, intelligence_key, mode):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, mode, count=0)
    cfg, paths = inventory(tmp_path, count=2, cfg=cfg)
    secret = "sk-proj-" + "b"*60
    for index, path in enumerate(paths):
        (path.parent / "helper.py").write_text(f"# Skill {index}\nTOKEN='{secret}'\nprint('private skill body {index}')\n")
    calls = []
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(remote(cfg, calls)))
    for _ in range(2):
        assert asyncio.run(worker.once()) is True
    assert asyncio.run(worker.once()) is False
    assert len(skill_calls(calls)) == 2
    assert all({row["path"] for row in json.loads(call.content)["files"]} == {"SKILL.md", "helper.py"} for call in skill_calls(calls))
    assert secret not in " ".join(call.content.decode() for call in calls)
    assert Store(cfg).summary() == dict(credits_charged="2", credits_reserved="0", unknown_attempts=0)
    persisted = (Path(cfg["data_dir"])/"posture-skills.json").read_bytes() + Store(cfg).path.read_bytes()
    assert b"private skill body" not in persisted and secret.encode() not in persisted
    later = assessments.time.time()+2*86400
    monkeypatch.setattr(assessments.time, "time", lambda: later)
    assert asyncio.run(worker.once()) is False and len(skill_calls(calls)) == 2
    for item in desktop_posture.read(cfg)["groups"]["skills"]["items"]:
        assert item["assessment_status"] == "partial" and "one billed request" in item["metadata"]["assessment_coverage"]


def test_changed_content_invalidates_projection_and_reads_do_not_capture_or_dispatch(tmp_path, monkeypatch, intelligence_key):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=0)
    cfg, (path,) = inventory(tmp_path, cfg=cfg)
    script = path.parent / "helper.py"
    script.write_text("print('original')\n")
    calls = []
    finding = dict(rule_id="SSD-1", message="Old content finding", severity="HIGH", start_line=1,
                   end_line=1, confidence=.8, explanation="Old content evidence", remediation="Review it.")
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(remote(cfg, calls, [finding])))
    assert asyncio.run(worker.once())
    assert desktop_posture.read(cfg)["groups"]["skills"]["items"][0]["findings"]
    script.write_text("print('changed')\n")
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(remote(cfg, calls)))
    assert asyncio.run(worker.once())
    current = desktop_posture.read(cfg)["groups"]["skills"]["items"][0]
    assert current["findings"] == [] and "one billed request" in current["metadata"]["assessment_coverage"]
    assert asyncio.run(worker.once()) is False and len(skill_calls(calls)) == 2
    path.write_text("New instructions not yet collected")
    assert asyncio.run(worker.once()) is False and len(skill_calls(calls)) == 2
    assert desktop_posture.read(cfg)["groups"]["skills"]["items"][0]["findings"] == []
    monkeypatch.setattr(skills, "capture", lambda *_args: pytest.fail("Reading posture captured files"))
    monkeypatch.setattr(assessments, "connection", lambda *_args: pytest.fail("Reading posture contacted the service"))
    assert desktop_posture.read(cfg)["groups"]["skills"]["items"]
    cfg["sensor_id"] = "new-device"
    cfg["posture"] = {"automatic": True, "scope": identity(cfg)}
    cfg.save()
    cache = InventoryService(cfg, None, components=True)
    snapshot = json.loads(cache.path.read_text())
    snapshot["identity"] = cache.identity
    cache.path.write_text(json.dumps(snapshot))
    item = desktop_posture.read(cfg)["groups"]["skills"]["items"][0]
    assert item["assessment_status"] == "pending" and item["findings"] == []
    assert "assessment_scope" not in item["metadata"] and Store(cfg).summary()["credits_charged"] == "0"


@pytest.mark.parametrize("failure", ["credits", "lost", "invalid_result", "partial_released"])
def test_skill_failures_preserve_charges_and_hold_unknown_tasks(tmp_path, monkeypatch, intelligence_key, failure):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=0)
    cfg, paths = inventory(tmp_path, count=2, cfg=cfg)
    (paths[1].parent / "extra.txt").write_text("A distinct second skill bundle")
    calls = []
    normal = remote(cfg, calls)
    def reject(request):
        if request.url.path != ENDPOINT:
            return normal(request)
        calls.append(request)
        if failure == "credits":
            return httpx.Response(402, json={"error": "credits_exhausted"})
        if failure == "lost":
            raise httpx.ReadTimeout("Response lost", request=request)
        value = response(json.loads(request.content), request.headers["idempotency-key"])
        if failure == "partial_released":
            value.update(status="error", code="provider_unavailable")
            value["result"]["coverage"].update(complete=False, files_completed=0, bytes_completed=0, batches_completed=0)
            value["billing"].update(state="released", credits_charged="0")
        else:
            value["result"] = {"findings": [{"summary": "Wrong schema"}]}
        return httpx.Response(200, json=value)
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(reject))
    assert asyncio.run(worker.once()) is False
    record, = Store(cfg).records().values()
    assert record["state"] == ("retry" if failure in ("credits", "partial_released") else "unknown")
    assert Store(cfg).summary()["credits_charged"] == ("1" if failure == "invalid_result" else "0")
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(normal))
    if failure == "credits":
        assert asyncio.run(worker.once()) is False and len(skill_calls(calls)) == 1
    later = assessments.time.time()+901
    monkeypatch.setattr(assessments.time, "time", lambda: later)
    remaining = 2 if failure in ("credits", "partial_released") else 1
    for _ in range(remaining):
        assert asyncio.run(worker.once()) is True
    assert asyncio.run(worker.once()) is False
    assert len(skill_calls(calls)) == 1+remaining
    assert Store(cfg).summary()["unknown_attempts"] == (0 if failure in ("credits", "partial_released") else 1)


@pytest.mark.parametrize("history", ["complete", "partial", "pending", "unknown", "missing_receipt", "other_scope"])
@pytest.mark.parametrize("map_exists", [False, True])
def test_legacy_ledger_reuse_and_uncertain_holds_do_not_depend_on_old_map(tmp_path, monkeypatch, intelligence_key, history, map_exists):
    cfg = configured(tmp_path, monkeypatch, intelligence_key, count=0)
    cfg, (path,) = inventory(tmp_path, cfg=cfg)
    (path.parent/"helper.py").write_text("print('another file')")
    candidate, = skills.candidates(cfg)
    keys = candidate["legacy_keys"]
    assert len(keys) == 2
    historical = Config(cfg.path, **dict(cfg))
    if history == "other_scope":
        historical["tenant_id"] = "00000000-0000-4000-8000-000000000002"
    store = Store(historical)
    for key in keys if history == "complete" else keys[:1]:
        request = store.claim("skill_assessment", [key])
        if history not in ("pending", "unknown", "missing_receipt"):
            store.receipt(request, dict(request_id=request, service="skill_assessment", state="settled",
                credits_reserved="1", credits_charged="1", rate_version="test.1"))
        if history == "unknown":
            store.fail(request)
        elif history != "pending":
            store.complete(request, {key:dict(status="partial", profile=skills.LEGACY_PROFILE,
                bundle_sha256=candidate["bundle_sha256"], checked_at=datetime.now(timezone.utc).isoformat(),
                expires_at=None, findings=[dict(title="Previous finding", detail="Retained evidence")])})
    if map_exists:
        (Path(cfg["data_dir"])/"posture-skills.json").write_text(json.dumps(dict(scope=identity(cfg), installations={})))
    calls = []
    normal = remote(cfg, calls)
    def reply(request):
        if request.url.path == ENDPOINT and history == "partial":
            item = desktop_posture.read(cfg)["groups"]["skills"]["items"][0]
            assert item["findings"][0]["title"] == "Previous finding"
            assert "Earlier partial findings retained" in item["metadata"]["assessment_coverage"]
        return normal(request)
    worker = assessments.Worker(cfg, transport=httpx.MockTransport(reply))
    charge = history in ("partial", "other_scope")
    assert asyncio.run(worker.once()) is charge
    assert asyncio.run(worker.once()) is False
    assert len(skill_calls(calls)) == int(charge)
    item = desktop_posture.read(cfg)["groups"]["skills"]["items"][0]
    if history == "complete":
        assert "Previous review retained" in item["metadata"]["assessment_coverage"]
    elif history in ("pending", "unknown", "missing_receipt"):
        assert "held" in item["metadata"]["assessment_coverage"]
    if history in ("complete", "partial", "missing_receipt"):
        assert item["findings"][0]["title"] == "Previous finding"
    usage = Store(cfg).summary()
    assert usage["credits_charged"] == ("2" if history in ("complete", "partial") else "1" if history == "other_scope" else "0")
    assert usage["unknown_attempts"] == (1 if history in ("pending", "unknown", "missing_receipt") else 0)
