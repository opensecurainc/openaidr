"""Real API/storage behavior behind a proxy enforcing a one-MiB request limit."""

import base64
import hashlib
import io
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.responses import Response

from openaidr.core.event import new_id, now
from openaidr.core.telemetry import encode_export
from openaidr.sensor.config import Config as SensorConfig
from openaidr.sensor.runtime import Client
from openaidr.sensor.telemetry import Telemetry
from openaidr.sensor import uploads
from openaidr.sensor.skill_bundles import capture, upload as upload_skills
from openaidr.server.app import create_app
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.config import Config
from test_app_inventory_server import app as application, snapshot, component, root, component_snapshot
from test_knowledge_uploads import document, payload, session
from test_store import db as db, sensor, tenant
from test_telemetry_server import export


@pytest.fixture
def connected(db):
    device, token, _ = sensor(db, tenant(db)["id"])
    cfg = Config(database_url=db.url)
    cfg.set_services("ingest,api")
    app = create_app(cfg, db)
    sizes = []
    app.state.fail_after_commit = False

    @app.middleware("http")
    async def proxy(request, call_next):
        size = len(await request.body())
        sizes.append(size)
        if size > 1 << 20:
            return Response(status_code=413)
        result = await call_next(request)
        if app.state.fail_after_commit and result.headers.get("x-openaidr-upload-complete") == "1":
            app.state.fail_after_commit = False
            return Response(status_code=503)
        return result

    client = Client("https://testserver", token)
    headers = dict(client.http.headers)
    client.http.close()
    client.http = TestClient(app, base_url=client.url, headers=headers)
    try:
        yield SimpleNamespace(db=db, device=device, token=token, app=app, client=client,
                              http=client.http, sizes=sizes, buffer=app.state.service.uploads)
    finally:
        client.close()


def fragments(content):
    headers = {"X-OpenAIDR-Upload-Id": str(uuid4()), "X-OpenAIDR-Upload-Length": str(len(content)),
               "X-OpenAIDR-Upload-SHA256": hashlib.sha256(content).hexdigest(),
               "Content-Type": "application/json"}
    return [(content[offset:offset + uploads.CHUNK_BYTES],
             {**headers, "X-OpenAIDR-Upload-Offset": str(offset)})
            for offset in range(0, len(content), uploads.CHUNK_BYTES)]


def test_large_events_reproduce_proxy_failure_then_deliver_without_loss(connected):
    s = connected
    events = [{"id": new_id(), "time": now(), "kind": "tool.result",
               "agent": {"product": "claude-code"}, "session": {"id": "large"},
               "tool": {"name": "Bash", "output": "中文 café " * 8000}} for _ in range(12)]
    data = {"sensor_id": s.device["id"], "events": events}
    assert s.http.post("/ingest/v1/events", json=data).status_code == 413
    s.sizes.clear()
    result = s.client.post("events", data)
    assert result == {"accepted": 12, "duplicates": 0, "rejected": []}
    assert s.client.post("events", data)["duplicates"] == 12
    assert max(s.sizes) <= uploads.CHUNK_BYTES
    for event in events:
        assert s.db.get_event(s.device["tenant_id"], event["id"])["body"]["tool"] == event["tool"]
    assert not s.buffer.items


@pytest.mark.parametrize("components", [False, True])
def test_inventory_remains_complete_through_interruption_and_bad_hash(connected, components):
    s = connected
    route = "inventory/snapshots" if components else "inventory/applications"
    table = "inventory_components" if components else "application_inventory"
    entry = component if components else application

    def body(items, offset=0):
        return component_snapshot([root(components=items)], offset) if components else snapshot(items, offset=offset)

    assert s.client.post(route, body([entry("previous")]))["accepted"]
    apps = [entry(str(index)) for index in range(300)]
    for item in apps:
        item["path"] = "/opt/" + "x" * 4000 + item["identifier"]
    data = body(apps, offset=1)
    parts = fragments(httpx.Request("POST", s.client.url, json=data).content)
    url = "/ingest/v1/uploads/" + route
    first = s.http.post(url, content=parts[0][0], headers=parts[0][1])
    assert first.status_code == 202
    assert s.db.scalar("SELECT count(*) FROM " + table) == 1
    # A server restart drops only incomplete staging. The retained full snapshot retries.
    s.buffer.items.clear()
    assert s.http.post(url, content=parts[1][0], headers=parts[1][1]).status_code == 409
    assert s.db.scalar("SELECT count(*) FROM " + table) == 1
    assert s.client.post(route, data)["accepted"]
    assert s.db.scalar("SELECT count(*) FROM " + table) == 300
    damaged = fragments(httpx.Request("POST", s.client.url, json=body([], offset=2)).content)
    chunk, headers = damaged[0]
    headers["X-OpenAIDR-Upload-SHA256"] = "0" * 64
    assert s.http.post(url, content=chunk, headers=headers).status_code == 400
    assert s.db.scalar("SELECT count(*) FROM " + table) == 300
    assert max(s.sizes) <= uploads.CHUNK_BYTES


def test_large_skill_bundle_arrives_intact(connected, tmp_path):
    s = connected
    skill = tmp_path / "skill"
    skill.mkdir()
    instructions = skill / "SKILL.md"
    instructions.write_text("---\nname: upload-test\ndescription: Test uploads\n---\nReview code.\n")
    for index in range(2):
        (skill / f"script{index}.py").write_text("#" + "x" * 900000)
    bundle = capture(str(instructions))
    data = component_snapshot([root(source="openaidr-skills", components=[component(
        "test", kind="skill", ecosystem="", path=str(instructions),
        metadata={"content_sha256": hashlib.sha256(instructions.read_bytes()).hexdigest()},
    )])])
    s.app.state.service.cfg.skill_scanner_token = "test-worker"
    assert s.client.post("inventory/snapshots", data)["accepted"]
    assert upload_skills(s.client, data)
    staged = s.app.state.service.skill_content.items[(s.device["tenant_id"], bundle["sha256"])][2]
    assert {name: base64.b64decode(value) for name, value in staged.items()} == {
        path.name: path.read_bytes() for path in skill.iterdir()
    }
    assert max(s.sizes) <= uploads.CHUNK_BYTES


@pytest.mark.parametrize("media", ["application/json", "application/x-protobuf"])
def test_large_telemetry_retains_queue_after_lost_reply_and_deduplicates(connected, tmp_path, media):
    s = connected
    cfg = SensorConfig(tmp_path / "sensor.yaml", data_dir=str(tmp_path / "data"),
                       server_url=s.client.url, sensor_id=s.device["id"], sensor_token=s.token)
    cfg.save()
    telemetry = Telemetry(cfg)
    data = export("logs")
    record = data["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    record["body"]["stringValue"] = "retained evidence " * 80000
    content = encode_export("logs", data, media)
    ident = telemetry.queue.append("logs", content, media, 1)
    telemetry.http.close()
    telemetry.http = TestClient(s.app, base_url=s.client.url)
    s.app.state.fail_after_commit = True
    try:
        assert telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 1
        telemetry.queue.retry(ident, "retry now", delay=0)
        assert telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 0
        assert s.db.scalar("SELECT count(*) FROM telemetry_exports WHERE batch_id=$1", ident) == 1
        assert max(s.sizes) <= uploads.CHUNK_BYTES
    finally:
        telemetry.close()


def test_knowledge_upload_preserves_file_and_checks_role_and_csrf_each_fragment(connected):
    s = connected
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject

    writer = PdfWriter(clone_from=io.BytesIO(document("pdf")))
    attachment = DecodedStreamObject()
    attachment.set_data(b"x" * (2 << 20))
    writer._add_object(attachment)
    output = io.BytesIO()
    writer.write(output)
    pdf = output.getvalue()
    data = payload(filename="operations.pdf", content=pdf)
    content = httpx.Request("POST", s.client.url, json=data).content
    parts = fragments(content)
    url = "/api/v1/knowledge/uploads/chunks"
    chunk, headers = parts[0]
    analyst = session(s.db, s.device["tenant_id"], "analyst")
    s.http.cookies.set(CONSOLE_COOKIE, analyst)
    assert s.http.post(url, content=chunk, headers=headers).status_code == 403
    headers = {**headers, "X-OpenAIDR-CSRF": "1", "Origin": s.app.state.service.cfg.public_url}
    assert s.http.post(url, content=chunk, headers={**headers, "Origin": "https://evil.example"}).status_code == 403
    s.http.cookies.set(CONSOLE_COOKIE, session(s.db, s.device["tenant_id"], "viewer"))
    assert s.http.post(url, content=chunk, headers=headers).status_code == 403
    s.http.cookies.set(CONSOLE_COOKIE, analyst)
    assert s.http.post(url, content=chunk, headers=headers).status_code == 202
    tail, tail_headers = parts[1]
    s.http.cookies.set(CONSOLE_COOKIE, session(s.db, s.device["tenant_id"], "viewer"))
    assert s.http.post(url, content=tail, headers={**tail_headers, "X-OpenAIDR-CSRF": "1"}).status_code == 403
    s.http.cookies.set(CONSOLE_COOKIE, session(s.db, s.device["tenant_id"], "analyst"))
    assert s.http.post(url, content=tail, headers={**tail_headers, "X-OpenAIDR-CSRF": "1"}).status_code == 409
    s.http.cookies.set(CONSOLE_COOKIE, analyst)
    result = uploads.post(s.http, "/api/v1/knowledge/uploads", content, chunk_url=url,
                          headers={"Content-Type": "application/json", "X-OpenAIDR-CSRF": "1"})
    assert result.status_code == 200, result.text
    assert "Orbitctl refresh rebuilds" in result.json()["passages"][0]["body"]
    assert max(s.sizes) <= uploads.CHUNK_BYTES


def test_fragment_authentication_ownership_limits_and_expiry(connected, monkeypatch):
    s = connected
    content = b'{"events":[]}' + b" " * uploads.CHUNK_BYTES
    parts = fragments(content)
    url = "/ingest/v1/uploads/events"
    first, headers = parts[0]
    assert s.http.post(url, content=first, headers={**headers, "Authorization": ""}).status_code == 401
    assert not s.buffer.items
    assert s.http.post(url, content=first, headers=headers).status_code == 202
    _, token, _ = sensor(s.db, tenant(s.db)["id"])
    last, last_headers = parts[1]
    assert s.http.post(url, content=last, headers={**last_headers, "Authorization": "Bearer " + token}).status_code == 409
    assert s.http.post(url + "/../inventory/applications", content=last, headers=last_headers).status_code == 409
    s.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", s.device["id"])
    assert s.http.post(url, content=last, headers=last_headers).status_code == 403
    s.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", s.device["id"])
    for changes, status in [({"X-OpenAIDR-Upload-Length": str((8 << 20) + 1)}, 413),
                            ({"X-OpenAIDR-Upload-Offset": "-1"}, 400),
                            ({"X-OpenAIDR-Upload-SHA256": "bad"}, 400)]:
        assert s.http.post(url, content=first, headers={**headers, **changes}).status_code == status
    assert s.http.post(url, content=first + b"x", headers=headers).status_code == 413
    monkeypatch.setattr(s.buffer, "MAX_BYTES", len(content))
    assert s.http.post(url, content=first, headers={**headers, "X-OpenAIDR-Upload-Id": str(uuid4())}).status_code == 429
    monkeypatch.setattr("openaidr.server.uploads.time", SimpleNamespace(monotonic=lambda: float("inf")))
    s.buffer.prune()
    assert not s.buffer.items
    assert s.http.post(url, content=last, headers=last_headers).status_code == 409


@pytest.mark.parametrize("status,headers", [(404, {}), (401, {}), (200, {}), (202, {"X-OpenAIDR-Upload-Offset": "wrong"})])
def test_sender_stops_on_unsupported_or_invalid_fragment_acknowledgment(status, headers):
    requests = []

    def reply(request):
        requests.append(request)
        return httpx.Response(status, headers=headers)

    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        if status >= 400:
            assert uploads.post(client, "https://test/events", b"x" * (2 << 20),
                                chunk_url="https://test/uploads/events").status_code == status
        else:
            with pytest.raises(ValueError, match="acknowledge"):
                uploads.post(client, "https://test/events", b"x" * (2 << 20),
                             chunk_url="https://test/uploads/events")
    assert len(requests) == 1 and len(requests[0].content) == uploads.CHUNK_BYTES
