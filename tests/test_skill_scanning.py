"""Skill uploads, tenant isolation, worker leases, and complete inventory totals."""

import base64
import copy
import json
import os
import subprocess
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from psycopg.types.json import Jsonb

import pytest
import httpx
from openaidr_api.threat_intel import keys
from openaidr_api_client.contracts.skills import MODEL, PROTOCOL, REVISION
from openaidr.server import skill_llm, skill_worker
from intelligence_service_fixtures import skill_service as service

from openaidr.core.skill_bundle import digest, validate_manifest, validate_files
from openaidr.sensor.skill_bundles import capture
from openaidr.server import skill_scanning
from openaidr.server.auth import CONSOLE_COOKIE
from openaidr.server.skill_worker import normalize, scan
from openaidr.server.skill_content import ContentBuffer
from test_app_inventory_server import inventory  # noqa: F401

API = "/api/v1/inventory/skills"
MANIFEST = "/ingest/v1/inventory/skills/manifest"
CONTENT = "/ingest/v1/inventory/skills/content"
WORKER = "/internal/v1/skill-scans/"


def bundle(script="print('hello')\n"):
    contents = {
        "SKILL.md": b"---\nname: review\ndescription: Review code\n---\nReview code.\n",
        "scripts/check.py": script.encode(),
    }
    manifest = {
        "version": 1,
        "complete": True,
        "files": sorted(
            [
                {"path": p, "size": len(data), "sha256": digest(data)}
                for p, data in contents.items()
            ],
            key=lambda f: f["path"],
        ),
    }
    return {
        "manifest": manifest,
        "sha256": validate_manifest(manifest)[0],
        "files": {p: base64.b64encode(data).decode() for p, data in contents.items()},
    }


def snapshot(data, *, offset=0, names=("review",)):
    return {
        "schema_version": 1,
        "platform": "darwin",
        "collected_at": (
            datetime.now(timezone.utc) + timedelta(seconds=offset)
        ).isoformat(),
        "roots": [
            {
                "source": "openaidr-skills",
                "root": "/skills",
                "scope": "user",
                "status": "ok",
                "relationships": [],
                "components": [
                    {
                        "key": name + "/SKILL.md",
                        "identifier": "/skills/" + name,
                        "name": name,
                        "kind": "skill",
                        "ecosystem": "",
                        "path": "/skills/" + name + "/SKILL.md",
                        "evidence": "installed",
                        "metadata": {
                            "content_sha256": next(
                                f["sha256"]
                                for f in data["manifest"]["files"]
                                if f["path"] == "SKILL.md"
                            )
                        },
                    }
                    for name in names
                ],
            }
        ],
    }


def headers(token):
    return {"Authorization": "Bearer " + token}


def upload(client, token, snap, data, name="review", *, content=True):
    request = {
        "reference": {
            "source": "openaidr-skills",
            "root": "/skills",
            "key": name + "/SKILL.md",
        },
        "collected_at": snap["collected_at"],
        "manifest": data["manifest"],
        "sha256": data["sha256"],
    }
    reply = client.post(MANIFEST, json=request, headers=headers(token))
    assert reply.status_code == 200, reply.text
    if reply.json()["needs_content"] and content:
        sent = client.post(
            CONTENT, json={**request, "files": data["files"]}, headers=headers(token)
        )
        assert sent.status_code == 200, sent.text
    return reply.json(), request


def enabled(inventory):
    st, cfg, client, identities = inventory
    cfg.tenant_id = identities[0][0]["tenant_id"]
    cfg.skill_scanner_token = "t" * 43
    return st, cfg, client, identities[0][1]


@pytest.fixture
def model_service(inventory, service, monkeypatch, tmp_path):
    st, cfg, client, sensor = enabled(inventory)
    cfg.intelligence_origin = "https://intel.example.com"
    key_file = tmp_path / "selected.key"
    keys.issue(service.db, cfg.tenant_id, key_file)
    cfg.intelligence_api_key = key_file.read_text().strip()
    cfg.openai_api_key = ""
    transport = SimpleNamespace(requests=[], responses=[], origins=None, urls=[], failure=None, keys={})
    direct_attempts = []
    real_http = httpx.HTTPTransport.handle_request

    def forbid_direct(client_transport, request):
        if request.url.host == "api.openai.com":
            direct_attempts.append(request)
            raise AssertionError("Selected mode attempted direct model transport")
        return real_http(client_transport, request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbid_direct)

    def forward(request):
        assert str(request.url) in [origin + "/v1/skills/assess" for origin in (transport.origins or [cfg.intelligence_origin])]
        transport.urls.append(str(request.url))
        origin = str(request.url).removesuffix("/v1/skills/assess")
        assert request.headers["authorization"] == "Bearer " + transport.keys.get(origin, cfg.intelligence_api_key)
        assert st.scalar("SELECT count(*) FROM model_usage WHERE status='pending'") > 0
        transport.requests.append(json.loads(request.content))
        if transport.failure == "lost":
            raise httpx.ConnectError("private-service-failure")
        answer = service.client.post(request.url.path, content=request.content, headers=dict(request.headers))
        value = answer.json()
        transport.responses.append((json.loads(request.content)["task"], answer.status_code, value.get("code")))
        if transport.failure == "hash":
            value["request_hash"] = "0" * 64
        return httpx.Response(answer.status_code, json=value)

    real_client = skill_llm.SyncIntelligenceClient.from_connection
    monkeypatch.setattr(skill_llm.SyncIntelligenceClient, "from_connection",
                        lambda connection: real_client(connection, transport=httpx.MockTransport(forward)))
    monkeypatch.setattr(skill_worker, "memory_directory", lambda: tmp_path)
    st.update_user(cfg.tenant_id, st.scalar("SELECT id FROM tenant_users WHERE tenant_id=$1", cfg.tenant_id), roles=["it_admin"])
    yield SimpleNamespace(st=st, cfg=cfg, client=client, sensor=sensor, transport=transport, service=service)
    assert not direct_attempts



def typed_task(job):
    return {"sha256": job["sha256"], "lease_id": job["lease_id"], "timeout_ms": 120000,
            "task": {"revision": REVISION, "task": "semantic_security_discovery", "bundle_sha256": job["sha256"],
                     "batch": {"file_path": "SKILL.md", "content": "# Example"}}}


def report(attention=False, complete=True):
    return {
        "complete": complete,
        "mode": "static",
        "score": 75 if attention else 0,
        "scanner_version": "2.12.0",
        "issues": [
            {
                "rule": "DE1",
                "severity": "HIGH",
                "title": "Credential exfiltration",
                "description": "Sends credentials to an external host.",
                "file": "scripts/check.py",
                "line": 2,
                "remediation": "Remove the upload.",
            }
        ]
        if attention
        else [],
    }


def claim(client, cfg, profile="test-v1"):
    reply = client.post(WORKER + "claim", headers=headers(cfg.skill_scanner_token),
                        json={"profile": profile})
    assert reply.status_code == 200, reply.text
    return reply.json()


def finish(client, cfg, job, result):
    return client.post(
        WORKER + "complete",
        headers=headers(cfg.skill_scanner_token),
        json={"sha256": job["sha256"], "lease_id": job["lease_id"], **result},
    )


@pytest.mark.parametrize("role", ["it_admin", "security_analyst"])
def test_skill_approval_is_content_scoped_durable_and_audited(inventory, role):
    st, cfg, client, token = enabled(inventory)
    sensor, _, session = inventory[3][0]
    other, other_token, other_session = inventory[3][1]
    tenant = sensor["tenant_id"]
    csrf = {"X-OpenAIDR-CSRF": "1"}
    data = bundle()
    snap = snapshot(data)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap).status_code == 200
    uncollected, = client.get(API).json()["items"]
    assert uncollected["approval_status"] == "unapproved"
    st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [role])
    path = f"{API}/{uncollected['id']}/approval"
    assert client.put(path, headers=csrf, json={"approved": True, "sha256": None}).status_code == 409
    assert client.put(path, headers=csrf, json={"approved": None, "sha256": None}).status_code == 200
    upload(client, token, snap, data)
    ident = data["sha256"]
    path = f"{API}/{ident}/approval"
    assert client.get(API).json()["items"][0]["approval_status"] == "unapproved"
    for denied in ("security_leadership",):
        st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [denied])
        assert client.put(path, headers=csrf, json={"approved": True, "sha256": ident}).status_code == 403
    st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", tenant, [role])
    assert client.put(path, json={"approved": True, "sha256": ident}).status_code == 403
    for invalid in ({}, {"approved": True}, {"approved": "yes", "sha256": ident},
                    {"approved": 1, "sha256": ident}, {"approved": True, "sha256": ident, "tenant": tenant}):
        assert client.put(path, headers=csrf, json=invalid).status_code == 400
    assert client.put(path, headers=csrf, json={"approved": True, "sha256": "b" * 64}).status_code == 409
    for decision, status in ((True, "approved"), (None, "monitoring"), (False, "unapproved"), (True, "approved")):
        saved = client.put(path, headers=csrf, json={"approved": decision, "sha256": ident})
        assert saved.status_code == 200, saved.text
        current, = client.get(API, params={"review": status}).json()["items"]
        assert current["approval_status"] == status
        assert current["approval_updated_at"] == saved.json()["approval_updated_at"]
        detail = client.get(f"{API}/{ident}").json()
        assert detail["approval_status"] == status
        assert client.get(API, params={"review": status}).json()["total"] == 1
    assert client.get(API, params={"review": "monitoring"}).json()["items"] == []
    assert client.get(API, params={"review": "bogus"}).status_code == 400
    # Scanner outcomes remain independent of the review choice.
    job = claim(client, cfg)["job"]
    assert finish(client, cfg, job, {"report": report(attention=True)}).status_code == 200
    current, = client.get(API, params={"review": "approved", "status": "attention"}).json()["items"]
    assert current["risk_score"] == 75 and current["needs_attention"]
    # Removal, reinstallation and an identical copy preserve the content choice.
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snapshot(data, offset=1, names=())).status_code == 200
    again = snapshot(data, offset=2, names=("review", "copy"))
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=again).status_code == 200
    for name in ("review", "copy"):
        upload(client, token, again, data, name)
    current, = client.get(API).json()["items"]
    assert current["approval_status"] == "approved" and current["installations"] == 2
    changed = bundle("print('changed')\n")
    newer = snapshot(changed, offset=3)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=newer).status_code == 200
    upload(client, token, newer, changed)
    current, = client.get(API).json()["items"]
    assert current["id"] == changed["sha256"] and current["approval_status"] == "unapproved"
    assert client.put(path, headers=csrf, json={"approved": True, "sha256": ident}).status_code == 404
    # An identical hash in another tenant starts with its own review state.
    cfg.tenant_id = other["tenant_id"]
    client.cookies.set(CONSOLE_COOKIE, other_session)
    st.execute("UPDATE tenant_users SET roles=$2 WHERE tenant_id=$1", other["tenant_id"], [role])
    assert client.get(f"{API}/{changed['sha256']}/devices").status_code == 404
    assert client.put(path, headers=csrf, json={"approved": None, "sha256": ident}).status_code == 404
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(other_token), json=snap).status_code == 200
    upload(client, other_token, snap, data)
    assert client.get(API).json()["items"][0]["approval_status"] == "unapproved"
    cfg.tenant_id = tenant
    client.cookies.set(CONSOLE_COOKIE, session)
    audit = st.many("SELECT details FROM audit_log WHERE tenant_id=$1 AND action='skill.approval' AND target_id=$2 ORDER BY at,id", tenant, ident)
    assert [row["details"]["before_status"] for row in audit] == ["unapproved", "approved", "monitoring", "unapproved"]
    assert [row["details"]["approved"] for row in audit] == [True, None, False, True]
    st.execute("""CREATE FUNCTION reject_skill_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='skill.approval' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
        RETURN NEW; END; $$""")
    st.execute("CREATE TRIGGER reject_skill_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_skill_audit()")
    assert client.put(f"{API}/{changed['sha256']}/approval", headers=csrf,
                      json={"approved": True, "sha256": changed["sha256"]}).status_code == 500
    assert client.get(API).json()["items"][0]["approval_status"] == "unapproved"


def test_skill_partial_content_cannot_inherit_approval_or_monitoring(inventory):
    st, cfg, client, token = enabled(inventory)
    tenant = cfg.tenant_id
    st.execute("UPDATE tenant_users SET roles=ARRAY['it_admin'] WHERE tenant_id=$1", tenant)
    data = bundle()
    data["manifest"]["complete"] = False
    data["manifest"]["files"].append({"path": "secret", "skip": "unreadable"})
    data["manifest"]["files"].sort(key=lambda item: item["path"])
    data["sha256"] = validate_manifest(data["manifest"])[0]
    snap = snapshot(data)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap).status_code == 200
    upload(client, token, snap, data, content=False)
    item, = client.get(API).json()["items"]
    path = f"{API}/{item['id']}/approval"
    csrf = {"X-OpenAIDR-CSRF": "1"}
    assert client.put(path, headers=csrf, json={"approved": True, "sha256": data["sha256"]}).status_code == 409
    assert client.put(path, headers=csrf, json={"approved": None, "sha256": data["sha256"]}).status_code == 200
    # A changed partial bundle keeps its installation ID but loses the old decision.
    data["manifest"]["files"][-1]["skip"] = "size_limit"
    data["sha256"] = validate_manifest(data["manifest"])[0]
    newer = snapshot(data, offset=1)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=newer).status_code == 200
    upload(client, token, newer, data, content=False)
    item, = client.get(API).json()["items"]
    assert item["approval_status"] == "unapproved"


def test_skill_notification_devices_are_distinct_and_not_truncated(inventory):
    st, cfg, client, token = enabled(inventory)
    sensor = inventory[3][0][0]
    enrollment = st.create_enrollment_token(sensor["tenant_id"])
    extra, extra_token, _ = st.enroll_sensor(dict(enrollment_token=enrollment["token"], hostname="z-last", os="linux"))
    data = bundle()
    names = tuple(["review"] + [f"copy-{i}" for i in range(201)])
    snap = snapshot(data, names=names)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap).status_code == 200
    for name in names:
        upload(client, token, snap, data, name, content=False)
    snap = snapshot(data)
    assert client.post("/ingest/v1/inventory/snapshots", headers=headers(extra_token), json=snap).status_code == 200
    upload(client, extra_token, snap, data, content=False)
    path = f"{API}/{data['sha256']}"
    assert client.get(path).json()["installations_truncated"]
    assert len(client.get(path).json()["installations"]) == 200
    devices = client.get(path + "/devices")
    assert devices.status_code == 200
    assert {row["id"] for row in devices.json()["items"]} == {sensor["id"], extra["id"]}
    st.execute("UPDATE sensors SET disabled=true WHERE id=$1", extra["id"])
    assert [row["id"] for row in client.get(path + "/devices").json()["items"]] == [sensor["id"]]
    st.execute("UPDATE sensors SET deleted_at=now() WHERE id=$1", sensor["id"])
    assert client.get(path + "/devices").json()["items"] == []


def test_upload_scan_identity_and_complete_totals(inventory):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data, names=("review", "copy"))
    assert (
        client.post(
            "/ingest/v1/inventory/snapshots", headers=headers(token), json=snap
        ).status_code
        == 200
    )
    assert client.get(API).json()["summary"]["installed"] == 2
    uncollected = client.get(API).json()["items"][0]
    uncollected_detail = client.get(API + "/" + uncollected["id"]).json()
    for item in (uncollected, uncollected_detail):
        assert item["sha256"] is None
        assert item["size_bytes"] is None
        assert item["bundle_complete"] is None
    upload(client, token, snap, data)
    persisted = json.dumps(st.many("SELECT * FROM skill_bundles"), default=str)
    assert "files" not in st.one("SELECT * FROM skill_bundles")
    assert data["files"]["scripts/check.py"] not in persisted
    assert "print('hello')" not in persisted
    duplicate, _ = upload(client, token, snap, data, "copy")
    assert duplicate["needs_content"] is False
    assert client.get(API).json()["summary"] == {
        "installed": 1,
        "installations": 2,
        "attention": 0,
        "assessed": 0,
        "pending": 1,
        "incomplete": 0,
    }
    for denied in (
        {},
        headers(token),
        headers("invalid"),
        {"Authorization": "Basic invalid"},
        [(b"authorization", b"Bearer \xe9")],
    ):
        for operation in ("claim", "complete"):
            assert (
                client.post(
                    WORKER + operation, headers=denied, json={"profile": "test-v1"}
                ).status_code
                == 401
            )
    claimed = client.post(
        WORKER + "claim",
        headers=headers(cfg.skill_scanner_token),
        json={"profile": "test-v1"},
    )
    assert claimed.status_code == 200, claimed.text
    job = claimed.json()["job"]
    assert job["files"] == data["files"]
    assert not client.app.state.service.skill_content.items
    assert (
        client.post(
            WORKER + "claim",
            headers=headers(cfg.skill_scanner_token),
            json={"profile": "test-v1"},
        ).json()["job"]
        is None
    )
    assert finish(client, cfg, job, {"report": report(True)}).status_code == 200
    assert finish(client, cfg, job, {"report": report(True)}).status_code == 409
    # A fresh server deduplicates with the retained result, not stored contents.
    client.app.state.service.skill_content = ContentBuffer()
    assert upload(client, token, snap, data)[0]["needs_content"] is False
    listing = client.get(API).json()
    assert listing["items"][0]["risk_score"] == 75
    assert listing["total"] == 1
    assert listing["summary"] == {
        "installed": 1,
        "installations": 2,
        "attention": 1,
        "assessed": 1,
        "pending": 0,
        "incomplete": 0,
    }
    detail = client.get(API + "/" + data["sha256"]).json()
    for item in (listing["items"][0], detail):
        assert item["sha256"] == data["sha256"]
        assert item["size_bytes"] == sum(f["size"] for f in data["manifest"]["files"])
        assert item["bundle_complete"] is True
    assert len(detail["installations"]) == 2
    assert detail["report"]["issues"][0]["file"] == "scripts/check.py"
    assert (
        "files" not in detail
    )  # File contents are never returned by the dashboard endpoint.
    assert (
        client.get(API, params={"q": "no-match"}).json()["summary"]
        == listing["summary"]
    )
    # A script-only change creates a new bundle, even with identical SKILL.md bytes.
    changed = bundle("print('changed')\n")
    newer = snapshot(changed, offset=1, names=("review", "copy"))
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=newer)
    upload(client, token, newer, changed)
    upload(client, token, newer, data, "copy")
    summary = client.get(API).json()["summary"]
    assert summary == {
        "installed": 2,
        "installations": 2,
        "attention": 1,
        "assessed": 1,
        "pending": 1,
        "incomplete": 0,
    }
    # An old upload cannot replace the current installation snapshot.
    old_request = {
        "reference": {
            "source": "openaidr-skills",
            "root": "/skills",
            "key": "review/SKILL.md",
        },
        "collected_at": snap["collected_at"],
        "manifest": data["manifest"],
        "sha256": data["sha256"],
    }
    assert (
        client.post(MANIFEST, headers=headers(token), json=old_request).status_code
        == 409
    )


def test_upload_auth_tampering_coverage_and_retry(inventory):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    _, request = upload(client, token, snap, data, content=False)
    assert client.post(MANIFEST, json=request).status_code == 401
    assert (
        client.post(
            MANIFEST, json=request, headers=headers(inventory[3][1][1])
        ).status_code
        == 403
    )
    assert (
        client.post(
            CONTENT,
            json={**request, "files": {**data["files"], "scripts/check.py": "eA=="}},
            headers=headers(token),
        ).status_code
        == 400
    )
    bad = copy.deepcopy(request)
    bad["manifest"]["files"][1]["path"] = "../escape.py"
    assert client.post(MANIFEST, json=bad, headers=headers(token)).status_code == 400
    upload(client, token, snap, data)
    job = claim(client, cfg, "test-v1")["job"]
    st.execute(
        "UPDATE skill_bundles SET lease_until=now()-interval '1 second' WHERE tenant_id=$1",
        cfg.tenant_id,
    )
    assert finish(client, cfg, job, {"report": report()}).status_code == 409
    assert claim(client, cfg, "test-v1")["job"] is None
    upload(client, token, snap, data)
    retry = claim(client, cfg, "test-v1")["job"]
    assert retry["lease_id"] != job["lease_id"]
    assert finish(client, cfg, retry, {"error": "timeout"}).status_code == 200
    assert client.get(API).json()["items"][0]["scan_status"] == "failed"
    assert client.get(API).json()["summary"]["assessed"] == 0
    assert claim(client, cfg, "test-v1")["job"] is None
    # New scanner configuration invalidates the cached assessment and can retry.
    assert claim(client, cfg, "test-v2")["job"] is None
    upload(client, token, snap, data)
    retry = claim(client, cfg, "test-v2")["job"]
    assert (
        finish(client, cfg, retry, {"report": report(complete=False)}).status_code
        == 200
    )
    partial = client.get(API).json()
    assert partial["items"][0]["scan_status"] == "partial"
    assert partial["items"][0]["risk_score"] is None
    assert partial["summary"]["incomplete"] == 1
    assert client.get(API).json()["summary"]["assessed"] == 0
    st.execute("UPDATE sensors SET disabled=true WHERE id=$1", inventory[3][0][0]["id"])
    assert (
        client.post(MANIFEST, json=request, headers=headers(token)).status_code == 403
    )


def test_scoped_read_and_quota(inventory, monkeypatch):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    # An identically named bundle in another tenant cannot read this tenant's result.
    assert (
        skill_scanning.overview(st, inventory[3][1][0]["tenant_id"], {}, True)[
            "summary"
        ]["installed"]
        == 0
    )
    with pytest.raises(Exception) as failure:
        skill_scanning.details(st, inventory[3][1][0]["tenant_id"], data["sha256"])
    assert failure.value.status == 404
    monkeypatch.setattr(skill_scanning, "MAX_TENANT_BUNDLES", 1)
    changed = bundle("new contents")
    req = {
        "reference": {
            "source": "openaidr-skills",
            "root": "/skills",
            "key": "review/SKILL.md",
        },
        "collected_at": snap["collected_at"],
        "manifest": changed["manifest"],
        "sha256": changed["sha256"],
    }
    assert client.post(MANIFEST, json=req, headers=headers(token)).status_code == 429


def test_capture_bounds_links_privacy_and_script_changes(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    instructions = skill / "SKILL.md"
    instructions.write_text("---\nname: review\n---\nReview code.")
    script = skill / "check.py"
    script.write_text("print('one')")
    first = capture(instructions)
    assert first["manifest"]["complete"]
    script.write_text("print('two')")
    assert capture(instructions)["sha256"] != first["sha256"]
    outside = tmp_path / "outside"
    outside.write_text("private")
    (skill / "link").symlink_to(outside)
    (skill / ".env").write_text("PRIVATE=secret")
    (skill / "large.bin").write_bytes(b"x" * ((1 << 20) + 1))
    os.mkfifo(skill / "pipe")
    result = capture(instructions)
    skips = {
        f["path"]: f.get("skip") for f in result["manifest"]["files"] if "skip" in f
    }
    assert skips == {
        ".env": "privacy",
        "large.bin": "size_limit",
        "link": "symlink",
        "pipe": "special_file",
    }
    assert result["manifest"]["complete"] is False
    assert set(validate_files(result["manifest"], result["files"])) == {
        "SKILL.md",
        "check.py",
    }


def test_worker_adapter_and_process_isolation(tmp_path, monkeypatch):
    raw = {
        "execution_successful": True,
        "risk_assessment": {"score": 0},
        "issues": [],
        "metadata": {
            "skillspector_version": "2.12.0",
            "llm_requested": False,
            "llm_available": False,
        },
        "analysis_completeness": {"is_complete": True},
    }
    data = bundle()
    assert normalize(raw, data["manifest"], "static")["complete"]
    assert not normalize(raw, data["manifest"], "llm")["complete"]
    assert not normalize(
        {**raw, "analysis_completeness": {}}, data["manifest"], "static"
    )["complete"]
    assert normalize(raw, data["manifest"], "static")["coverage"] == {"reasons": [], "truncated": False}
    # External scanner stub exercises actual materialization and process execution.
    executable = tmp_path / "python"
    executable.write_text(
        "#!/usr/bin/env python3\nimport os,sys,json\nfrom pathlib import Path\nsys.argv=sys.argv[2:]\n"
        "assert 'OPENAIDR_DATABASE_URL' not in os.environ\n"
        "assert Path(sys.argv[2], 'scripts/check.py').read_text().startswith('print')\n"
        "assert '--no-llm' in sys.argv\n"
        f"Path(sys.argv[sys.argv.index('--output')+1]).write_text({json.dumps(json.dumps(raw))})\n"
    )
    executable.chmod(0o755)
    monkeypatch.setenv("OPENAIDR_DATABASE_URL", "must-not-be-inherited")
    # Synthetic test files may use the test directory; real scans reject disk.
    from openaidr.server import skill_worker
    monkeypatch.setattr(skill_worker, "memory_directory", lambda: tmp_path)
    assert scan(data, binary=str(executable))["complete"]
    assert not list(tmp_path.glob("openaidr-skill-*"))
    executable.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n")
    with pytest.raises(subprocess.TimeoutExpired):
        scan(data, binary=str(executable), timeout=0.01)
    assert not list(tmp_path.glob("openaidr-skill-*"))


@pytest.mark.parametrize("mode,managed", [("static", False), ("llm", False), ("llm", True)])
def test_intelligence_expiry_preserves_age_and_never_reschedules_paid_model_analysis(inventory, mode, managed):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    value = {**report(True), "mode": mode, "intel_expires_at": expiry}
    for invalid in (42, "not-a-date", "2026-01-01T00:00:00", "0001-01-01T00:00:00+01:00",
                    (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()):
        assert finish(client, cfg, job, {"report": {**value, "intel_expires_at": invalid}}).status_code == 400
    assert finish(client, cfg, job, {"report": value}).status_code == 200
    assert client.get(API + "/" + data["sha256"]).json()["report"]["intel_expires_at"] == expiry
    assert client.get(API).json()["items"][0]["scan_status"] == "complete"
    assert claim(client, cfg)["job"] is None
    # Simulate crossing the provider expiry while the report is still newly completed.
    st.execute("""UPDATE skill_bundles SET report=jsonb_set(report,'{intel_expires_at}',
        to_jsonb((now()-interval '1 second')::text))""")
    if managed:
        st.execute("UPDATE skill_bundles SET report=report || '{\"llm_cache\":true}'::jsonb")
    item = client.get(API).json()["items"][0]
    assert item["scan_status"] == "stale" and item["risk_score"] is None
    assert item["retained_score"] == value["score"]
    assert client.get(API + "/" + data["sha256"]).json()["report"]["issues"] == skill_scanning.validate_report(value)["issues"]
    response, _ = upload(client, token, snap, data)
    if mode == "static":
        assert response["needs_content"] is True
        assert claim(client, cfg)["job"] is not None
    else:
        assert response["needs_content"] is False
        assert claim(client, cfg)["job"] is None
        assert st.scalar("SELECT count(*) FROM skill_llm_jobs") == 0


def test_enabling_intelligence_gateway_does_not_schedule_new_managed_model_jobs(inventory):
    from openaidr.server.skill_worker import scanner_profile

    st, cfg, client, token = enabled(inventory)
    data, model = bundle(), {"SKILLSPECTOR_MODEL": "gpt-6-luna", "SKILLSPECTOR_REASONING_EFFORT": "none"}
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    original_profile = scanner_profile("static", {})
    original_model_profile = scanner_profile("llm", model) + ":metered-1"
    job = claim(client, cfg, original_profile)["job"]
    value = {**report(True), "mode": "llm"}
    assert finish(client, cfg, job, {"report": value}).status_code == 200
    st.execute("""INSERT INTO skill_llm_jobs(id,tenant_id,sha256,profile,status,report,completed_at)
        VALUES(gen_random_uuid(),$1,$2,$3,'complete',$4,now())""", cfg.tenant_id, data["sha256"],
        original_model_profile, Jsonb(skill_scanning.validate_report(value)))
    st.execute("INSERT INTO tenant_skill_llm_settings(tenant_id,mode,budget_usd) VALUES($1,'automatic',10)", cfg.tenant_id)
    gateway = "https://intel.example.com"
    new_profile = scanner_profile("static", {}, intel_origin=gateway)
    new_model_profile = scanner_profile("llm", model, intel_origin=gateway) + ":metered-1"
    assert new_profile != original_profile and new_model_profile == original_model_profile
    response = client.post(WORKER + "claim", headers=headers(cfg.skill_scanner_token),
                           json={"profile": new_profile, "llm_profile": new_model_profile})
    assert response.status_code == 200 and response.json()["job"] is None
    assert st.scalar("SELECT count(*) FROM skill_llm_jobs") == 1
    assert st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE status='pending'") == 0
    retained = client.get(API + "/" + data["sha256"]).json()["report"]
    assert retained["llm_cache"] and retained["issues"] == skill_scanning.validate_report(value)["issues"]
    assert "intel_expires_at" not in retained


def test_partial_score_and_bounded_coverage_survive_worker_api_storage(inventory):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    exception = {"reason_code": "reference_missing", "message": "Referenced file is missing.",
                 "path": "references/guide.md", "analyzers": ["references", "semantic"], "raw_content": "do not retain"}
    raw = {
        "execution_successful": True, "risk_assessment": {"score": 82},
        "metadata": {"skillspector_version": "2.12.0"},
        "issues": [{"severity": "HIGH", "id": "DE1", "finding": "Synthetic finding"}],
        "analysis_completeness": {"is_complete": False, "ledger_exceptions": [exception],
                                  "limitations": ["Analyzer coverage was incomplete."], "file_contents": "do not retain"},
    }
    normalized = normalize(raw, data["manifest"], "static")
    assert not normalized["complete"]
    for invalid in (
        None, {"reasons": [], "truncated": 0}, {"reasons": [{}], "truncated": False},
        {"reasons": [{"message": "x" * 513}], "truncated": False},
        {"reasons": [{"message": "reason"}] * 51, "truncated": False},
    ):
        assert finish(client, cfg, job, {"report": {**normalized, "coverage": invalid}}).status_code == 400
    assert finish(client, cfg, job, {"report": normalized}).status_code == 200
    listing = client.get(API).json()
    item = listing["items"][0]
    assert item["risk_score"] is None and item["retained_score"] == 82
    assert item["scan_status"] == "partial" and item["needs_attention"]
    assert listing["summary"]["assessed"] == 0 and listing["summary"]["pending"] == 1
    detail = client.get(API + "/" + item["id"]).json()
    assert detail["report"]["coverage"] == {"reasons": [
        {"code": "reference_missing", "message": "Referenced file is missing.", "file": "references/guide.md", "analyzer": "references, semantic"},
        {"code": "scanner_limitation", "message": "Analyzer coverage was incomplete.", "file": "", "analyzer": ""},
    ], "truncated": False}
    stored = st.one("SELECT * FROM skill_bundles")
    assert "do not retain" not in json.dumps(stored, default=str)
    assert "files" not in stored
    # Oversized diagnostics are bounded, with an explicit indication of loss.
    raw["analysis_completeness"]["ledger_exceptions"] = [
        {**exception, "path": str(n), "message": "x" * 600} for n in range(60)
    ]
    bounded = normalize(raw, data["manifest"], "static")["coverage"]
    assert bounded["truncated"] and len(bounded["reasons"]) == 50
    assert all(len(reason["message"]) == 512 for reason in bounded["reasons"])
    # Older workers remain accepted without fabricating a coverage explanation.
    assert "coverage" not in skill_scanning.validate_report(report())


@pytest.mark.parametrize("scanner_complete", [True, False])
def test_shortened_finding_text_preserves_scanner_coverage(inventory, scanner_complete):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    raw = {
        "execution_successful": True, "risk_assessment": {"score": 82},
        "metadata": {"skillspector_version": "2.12.0"},
        "issues": [{"severity": "HIGH", "finding": "Synthetic finding", "explanation": "x" * 4097}],
        "analysis_completeness": {"is_complete": scanner_complete, "ledger_exceptions": [] if scanner_complete else [
            {"reason_code": "reference_missing", "message": "Required file is missing.", "path": "SKILL.md"},
        ]},
    }
    normalized = normalize(raw, data["manifest"], "static")
    assert normalized["complete"] is scanner_complete
    assert normalized["finding_text_truncated"] is True
    assert len(normalized["issues"][0]["description"]) == 4096
    assert finish(client, cfg, job, {"report": {**normalized, "finding_text_truncated": "true"}}).status_code == 400
    assert finish(client, cfg, job, {"report": normalized}).status_code == 200
    listing = client.get(API).json()
    item = listing["items"][0]
    assert item["scan_status"] == ("complete" if scanner_complete else "partial")
    assert item["risk_score"] == (82 if scanner_complete else None)
    assert item["retained_score"] == 82 and item["needs_attention"]
    assert listing["summary"]["assessed"] == int(scanner_complete)
    assert listing["summary"]["incomplete"] == int(not scanner_complete)
    saved = client.get(API + "/" + item["id"]).json()["report"]
    assert saved["finding_text_truncated"] is True
    assert [reason["code"] for reason in saved["coverage"]["reasons"]] == ([] if scanner_complete else ["reference_missing"])


def reference_scan(source, references):
    # Public report shape reproduced with the pinned scanner in --no-llm mode.
    data = bundle()
    content = source.encode()
    data["files"] = {"SKILL.md": base64.b64encode(content).decode()}
    data["manifest"]["files"] = [{"path": "SKILL.md", "size": len(content), "sha256": digest(content)}]
    data["sha256"] = validate_manifest(data["manifest"])[0]
    records = []
    for target, kind in references:
        offset = source.index(target)
        records.append({"source_path": "SKILL.md", "line": source[:offset].count("\n") + 1,
                        "column": offset - source.rfind("\n", 0, offset), "target_path": None,
                        "status": "missing", "reference_kind": kind, "disposition": "partial",
                        "evidence": "RAW SOURCE MUST NOT BE RETAINED"})
    raw = {
        "execution_successful": True, "metadata": {"skillspector_version": "2.12.0"},
        "risk_assessment": {"score": 0}, "issues": [],
        "analysis_completeness": {
            "is_complete": False, "status": "partial", "execution_successful": True,
            "total_components": 1, "scanned_components": 1, "fully_inspected_files": 1,
            "coverage_percent": 100.0, "partially_inspected_files": 0, "entirely_uninspected_files": 0,
            "limitations": [], "scope_exclusions": [], "references": records,
            "ledger_exceptions": [{"reason_code": "reference_missing", "path": "SKILL.md",
                                   "start_line": row["line"], "end_line": row["line"],
                                   "phase": "reference_resolution", "outcome": "partial", "fatal": False}
                                  for row in records],
        },
    }
    return data, raw


@pytest.mark.parametrize("missing_input", [False, True])
def test_reference_classification_survives_worker_api_storage(inventory, missing_input):
    st, cfg, client, token = enabled(inventory)
    source = "---\nname: report\ndescription: Write a report.\n---\n"
    refs = []
    if missing_input:
        source += "Read [the guide](references/guide.md).\n"
        refs.append(("references/guide.md", "markdown_link"))
    source += "```sh\nprintf sample > ./report.txt\n```\n"
    refs.append(("./report.txt", "plain_path"))
    data, raw = reference_scan(source, refs)
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    normalized = normalize(raw, data["manifest"], "static", source_files=validate_files(data["manifest"], data["files"]))
    assert normalized["complete"] is not missing_input
    reasons = normalized["coverage"]["reasons"]
    assert reasons[-1]["code"] == "reference_generated_output"
    assert reasons[-1]["target"] == "report.txt" and reasons[-1]["line"] == (7 if missing_input else 6)
    if missing_input:
        assert reasons[0]["code"] == "reference_missing_input"
        assert reasons[0]["target"] == "references/guide.md" and reasons[0]["line"] == 5
    for invalid in ({"line": True}, {"line": -1}, {"line": 10_000_001}, {"target": 5}, {"target": "x" * 2049}):
        bad = copy.deepcopy(normalized)
        bad["coverage"]["reasons"][0].update(invalid)
        assert finish(client, cfg, job, {"report": bad}).status_code == 400
    assert finish(client, cfg, job, {"report": normalized}).status_code == 200
    listing = client.get(API).json()
    item = listing["items"][0]
    assert item["scan_status"] == ("partial" if missing_input else "complete")
    assert listing["summary"]["assessed"] == int(not missing_input)
    saved = client.get(API + "/" + item["id"]).json()["report"]
    assert saved["coverage"] == normalized["coverage"]
    assert "RAW SOURCE" not in json.dumps(saved) and "printf sample" not in json.dumps(saved)


def test_reference_classification_is_conservative():
    for source, target, kind, expected in (
        ("```sh\necho hello > ./out.txt\n```", "./out.txt", "plain_path", "reference_generated_output"),
        ("~~~bash\nprintf text >> './out.txt'\n~~~", "./out.txt", "quoted_or_code", "reference_generated_output"),
        ("```zsh\nprintf text 2>./out.txt\n```", "./out.txt", "plain_path", "reference_generated_output"),
        ("```sh\ncat < ./in.txt > ./out.txt\n```", "./in.txt", "plain_path", "reference_missing"),
        ("```sh\npython run.py --output ./out.txt\n```", "./out.txt", "plain_path", "reference_missing"),
        ("`echo hello > ./out.txt`", "./out.txt", "plain_path", "reference_missing"),
        ("```python\nvalue > './out.txt'\n```", "./out.txt", "quoted_or_code", "reference_missing"),
        ("```sh\necho hello > ./out.txt\n", "./out.txt", "plain_path", "reference_missing"),
        ("```sh\ncat << EOF\necho hello > ./out.txt\nEOF\n```", "./out.txt", "plain_path", "reference_missing"),
        ("```sh\necho $(cat ./in.txt) > ./out.txt\n```", "./out.txt", "plain_path", "reference_missing"),
        ("```sh\necho hello > ./out.txt; cat ./input.txt\n```", "./out.txt", "plain_path", "reference_missing"),
        ("```sh\necho hello > './out.txt'suffix\n```", "./out.txt", "quoted_or_code", "reference_missing"),
        ("~~~~text\n```sh\necho hello > ./out.txt\n```\n~~~~", "./out.txt", "plain_path", "reference_missing"),
        ("~~~~text `example`\n```sh\necho hello > ./out.txt\n```\n~~~~", "./out.txt", "plain_path", "reference_missing"),
        ("<pre>\n```sh\necho hello > ./out.txt\n```\n</pre>", "./out.txt", "plain_path", "reference_missing"),
        ("<!--\n```sh\necho hello > ./out.txt\n```\n-->", "./out.txt", "plain_path", "reference_missing"),
        ("Run `node node_modules/tool/main.js`.", "node_modules/tool/main.js", "inline_command", "reference_external_dependency"),
        ("Run `python scripts/missing.py`.", "scripts/missing.py", "inline_command", "reference_missing_input"),
        ("Read [guide](references/a%20b.md).", "references/a%20b.md", "markdown_link", "reference_missing_input"),
    ):
        data, raw = reference_scan(source, [(target, kind)])
        result = normalize(raw, data["manifest"], "static", source_files=validate_files(data["manifest"], data["files"]))
        assert result["coverage"]["reasons"][0]["code"] == expected, source
        assert result["complete"] is (expected == "reference_generated_output"), source
    # Separate input and output occurrences on the same line cannot be waived.
    data, raw = reference_scan("```sh\ncat ./input.txt > ./out.txt\n```", [
        ("./input.txt", "plain_path"), ("./out.txt", "plain_path"),
    ])
    result = normalize(raw, data["manifest"], "static", source_files=validate_files(data["manifest"], data["files"]))
    assert not result["complete"] and len(result["coverage"]["reasons"]) == 2
    source = "```sh\ncat ./out.txt > ./out.txt\n```"
    data, raw = reference_scan(source, [("./out.txt", "plain_path"), ("./out.txt", "plain_path")])
    raw["analysis_completeness"]["references"][1]["column"] = source.split("\n")[1].rfind("./out.txt") + 1
    result = normalize(raw, data["manifest"], "static", source_files=validate_files(data["manifest"], data["files"]))
    assert not result["complete"]
    assert [reason["code"] for reason in result["coverage"]["reasons"]] == ["reference_missing", "reference_generated_output"]


def test_generated_outputs_cannot_hide_other_coverage_gaps():
    data, raw = reference_scan("```sh\nprintf sample > ./out.txt\n```", [("./out.txt", "plain_path")])
    files = validate_files(data["manifest"], data["files"])
    assert not normalize(raw, data["manifest"], "static")["complete"]
    assert not normalize(raw, {**data["manifest"], "complete": False}, "static", source_files=files)["complete"]
    assert not normalize(raw, data["manifest"], "llm", source_files=files)["complete"]
    for field, value in (("total_components", 2), ("scanned_components", 0), ("partially_inspected_files", 1),
                         ("entirely_uninspected_files", 1), ("execution_successful", False),
                         ("limitations", ["Analyzer failed."]), ("scope_exclusions", [{"path": "ignored.txt"}])):
        changed = copy.deepcopy(raw)
        changed["analysis_completeness"][field] = value
        assert not normalize(changed, data["manifest"], "static", source_files=files)["complete"], field
    for code in ("static_parse_limit", "reference_extraction_limit", "obfuscated_instruction_text", "unknown_reason"):
        changed = copy.deepcopy(raw)
        changed["analysis_completeness"]["ledger_exceptions"].append({"reason_code": code, "path": "SKILL.md"})
        result = normalize(changed, data["manifest"], "static", source_files=files)
        assert not result["complete"] and result["coverage"]["reasons"][-1]["code"] == code
    ambiguous = copy.deepcopy(raw)
    ambiguous["analysis_completeness"]["references"][0]["status"] = "ambiguous"
    assert not normalize(ambiguous, data["manifest"], "static", source_files=files)["complete"]
    # Evidence and counts cannot substitute for the original source coordinates.
    for field, value in (("line", 1000), ("column", 0), ("source_path", "missing.md")):
        changed = copy.deepcopy(raw)
        changed["analysis_completeness"]["references"][0][field] = value
        assert not normalize(changed, data["manifest"], "static", source_files=files)["complete"]


def test_worker_never_exports_retained_model_keys(inventory):
    st, cfg, client, sensor_token = enabled(inventory)
    endpoint = WORKER + "model-key"
    for credential in (None, sensor_token, "wrong-worker-token"):
        response = client.post(endpoint, json={}, headers=headers(credential) if credential else {})
        assert response.status_code == 401
    cfg.openai_api_key = "historical-provider-key"
    st.execute("INSERT INTO tenant_model_keys(tenant_id,kind,api_key) VALUES($1,'detection','historical-database-key')", cfg.tenant_id)
    response = client.post(endpoint, json={}, headers=headers(cfg.skill_scanner_token))
    assert response.status_code == 409
    assert "historical" not in response.text
    assert client.post(WORKER + "model-mode", json={}, headers=headers(cfg.skill_scanner_token)).status_code == 503


def test_luna_configuration_and_usage_report(inventory, tmp_path, monkeypatch):
    from openaidr.server.skill_worker import model_environment, scanner_profile

    key = tmp_path / "test-key"
    key.write_text("synthetic-key")
    monkeypatch.setenv("OPENAIDR_SKILL_SCAN_API_KEY_FILE", str(key))
    class Backend:
        def post(self, *args, **kwargs):
            return httpx.Response(200, json={"service": "intelligence", "model": MODEL}, request=httpx.Request("POST", "https://tenant.test"))
    monkeypatch.setenv("OPENAIDR_SKILL_SCAN_MODEL", MODEL)
    env = model_environment("llm", Backend())
    assert "OPENAI_API_KEY" not in env and env["SKILLSPECTOR_REASONING_EFFORT"] == "none"
    assert scanner_profile("llm", env) != scanner_profile("llm", {**env, "SKILLSPECTOR_REASONING_EFFORT": "low"})
    for value in ("gpt-5.4", ""):
        monkeypatch.setenv("OPENAIDR_SKILL_SCAN_MODEL", value)
        with pytest.raises(ValueError, match="gpt-6-luna"):
            model_environment("llm", Backend())
    with pytest.raises(ValueError, match="tenant worker"):
        model_environment("llm")

    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    record = {"usage_source": "provider_response", "provider": "openai", "model": "gpt-6-luna",
              "prompt_tokens": 1000, "completion_tokens": 200, "cached_tokens": 100,
              "cache_write_tokens": 50, "reasoning_tokens": 0}
    raw = {"execution_successful": True, "risk_assessment": {"score": 45}, "issues": [],
           "metadata": {"skillspector_version": "2.12.0", "llm_requested": True, "llm_available": True,
                        "inference_usage": [{**record, "prompt": "must-not-retain", "response": "must-not-retain"},
                                            {"usage_source": "provider_response", "provider": "openai", "model": "gpt-6-luna", "prompt_tokens": 0}]},
           "analysis_completeness": {"is_complete": False}}
    result = normalize(raw, data["manifest"], "llm", model="gpt-6-luna")
    assert not result["complete"] and result["model"] == "gpt-6-luna"
    assert result["inference_usage"][0] == record
    assert "completion_tokens" not in result["inference_usage"][1]
    for bad in ({**record, "prompt_tokens": True}, {**record, "cached_tokens": 1001},
                {**record, "completion_tokens": -1}, {**record, "model": "sk-secret"},
                {**record, "usage_source": "estimated"}):
        assert finish(client, cfg, job, {"report": {**result, "inference_usage": [bad]}}).status_code == 400
    assert finish(client, cfg, job, {"report": result}).status_code == 200
    detail = client.get(API + "/" + data["sha256"]).json()
    assert "model" not in detail["report"] and "inference_usage" not in detail["report"]
    retained = st.scalar("SELECT report FROM skill_bundles")
    assert retained["model"] == "gpt-6-luna" and retained["inference_usage"] == result["inference_usage"]
    assert "must-not-retain" not in json.dumps(st.one("SELECT * FROM skill_bundles"), default=str)
    assert "inference_usage" not in skill_scanning.validate_report(report())

    raw["issues"] = [{"severity": "HIGH", "finding": "Retain this finding"}]
    for model in ("ft:gpt-4o:org::id", "openai/gpt-6-luna"):
        projected = normalize(raw, data["manifest"], "llm", model=model)
        assert projected["model"] == model and projected["needs_attention"]
    for invalid in (None, "must-not-retain", [record] * 4097,
                    [{**record, "prompt_tokens": True}], [{"model": "sk-secret"}]):
        raw["metadata"]["inference_usage"] = invalid
        projected = normalize(raw, data["manifest"], "llm", model="gpt-6-luna")
        assert projected["usage_incomplete"] and projected["score"] == 45
        assert projected["needs_attention"] and projected["issues"][0]["title"] == "Retain this finding"
        assert "inference_usage" not in projected
        assert "must-not-retain" not in json.dumps(projected)
    raw["metadata"].pop("inference_usage")
    projected = normalize(raw, data["manifest"], "llm", model="sk-secret")
    assert "model" not in projected and projected["needs_attention"] and projected["usage_incomplete"]
    projected = normalize(raw, data["manifest"], "llm", model="gpt-6-luna")
    assert "inference_usage" not in projected and projected["needs_attention"]


def test_worker_requires_memory_backed_scratch(tmp_path, monkeypatch):
    from openaidr.server import skill_worker

    monkeypatch.setattr(skill_worker.tempfile, "gettempdir", lambda: str(tmp_path))
    mounts = [SimpleNamespace(mountpoint="/", fstype="ext4")]
    monkeypatch.setattr(skill_worker.psutil, "disk_partitions", lambda **kw: mounts)
    with pytest.raises(RuntimeError, match="memory-backed"):
        scan(bundle(), binary="must-not-run")
    assert not list(tmp_path.glob("openaidr-skill-*"))
    mounts.append(SimpleNamespace(mountpoint=str(tmp_path), fstype="tmpfs"))
    assert skill_worker.memory_directory() == tmp_path.resolve()


def test_content_loss_capacity_expiry_and_reassessment(inventory, monkeypatch):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    buffer = client.app.state.service.skill_content
    monkeypatch.setattr(buffer, "MAX_BYTES", 1)
    _, request = upload(client, token, snap, data, content=False)
    reply = client.post(CONTENT, json={**request, "files": data["files"]}, headers=headers(token))
    assert reply.status_code == 429
    assert not buffer.items
    assert st.one("SELECT status FROM skill_bundles")["status"] == "awaiting_upload"
    monkeypatch.setattr(buffer, "MAX_BYTES", ContentBuffer.MAX_BYTES)
    upload(client, token, snap, data)
    # Simulate a backend process restart. Metadata survives; contents do not.
    client.app.state.service.skill_content = ContentBuffer()
    assert claim(client, cfg)["job"] is None
    assert st.one("SELECT status FROM skill_bundles")["status"] == "awaiting_upload"
    assert upload(client, token, snap, data)[0]["needs_content"]
    # Idle payloads expire even if the scanner has stopped polling.
    from openaidr.server import skill_content
    buffer = client.app.state.service.skill_content
    expiry = next(iter(buffer.items.values()))[0]
    with monkeypatch.context() as clock:
        clock.setattr(skill_content.time, "monotonic", lambda: expiry + 1)
        buffer.prune()
    assert not buffer.items
    assert upload(client, token, snap, data)[0]["needs_content"]
    job = claim(client, cfg)["job"]
    assert not buffer.items
    assert not upload(client, token, snap, data)[0]["needs_content"]
    assert finish(client, cfg, job, {"report": report()}).status_code == 200
    # Reassessment needs a new upload and gets a fresh attempt budget each day.
    for _ in range(4):
        st.execute("UPDATE skill_bundles SET completed_at=now()-interval '2 days'")
        assert claim(client, cfg)["job"] is None
        assert upload(client, token, snap, data)[0]["needs_content"]
        job = claim(client, cfg)["job"]
        assert st.one("SELECT attempts FROM skill_bundles")["attempts"] == 1
        assert finish(client, cfg, job, {"report": report()}).status_code == 200


def test_migration_removes_legacy_contents_and_keeps_results(inventory):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data, names=("review", "copy"))
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    finish(client, cfg, job, {"report": report(True)})
    upload(client, token, snap, bundle("changed"), "copy")
    # Recreate the old content column to exercise an upgrade with retained data.
    st.execute("ALTER TABLE skill_bundles ADD COLUMN files jsonb")
    st.execute("UPDATE skill_bundles SET files=$1", Jsonb(data["files"]))
    migration = Path(skill_scanning.__file__).parent / "migrations/0095_ephemeral_skill_content.sql"
    with st.transaction() as conn:
        conn.execute(migration.read_text())
    rows = st.many("SELECT * FROM skill_bundles ORDER BY sha256")
    assert all("files" not in row for row in rows)
    completed = next(row for row in rows if row["sha256"] == data["sha256"])
    assert completed["report"]["score"] == 75
    assert completed["status"] == "complete"
    assert all(row["lease_id"] is None and row["lease_until"] is None for row in rows)
    assert next(row for row in rows if row != completed)["status"] == "awaiting_upload"


def test_inventory_totals_cover_every_page(inventory):
    _, _, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data, names=tuple(f"skill-{n}" for n in range(57)))
    assert (
        client.post(
            "/ingest/v1/inventory/snapshots", headers=headers(token), json=snap
        ).status_code
        == 200
    )
    first = client.get(API).json()
    second = client.get(API, params={"cursor": first["next_cursor"]}).json()
    assert first["summary"]["installed"] == second["summary"]["installed"] == 57
    assert len(first["items"]) == 50 and len(second["items"]) == 7
    assert not set(i["id"] for i in first["items"]) & set(
        i["id"] for i in second["items"]
    )
    assert not second["next_cursor"]


@pytest.mark.parametrize("partial", [False, True])
def test_bundle_metadata_reports_zero_and_partial_collection(inventory, partial):
    st, cfg, client, token = enabled(inventory)
    manifest = {
        "version": 1,
        "complete": not partial,
        "files": [{"path": "SKILL.md", "size": 0, "sha256": digest(b"")}],
    }
    if partial:
        manifest["files"].append({"path": "private.env", "skip": "privacy"})
    data = {"manifest": manifest, "sha256": validate_manifest(manifest)[0]}
    snap = snapshot(data, names=("review", "copy"))
    assert client.post(
        "/ingest/v1/inventory/snapshots", headers=headers(token), json=snap
    ).status_code == 200
    for name in ("review", "copy"):
        upload(client, token, snap, data, name, content=False)
    items = client.get(API).json()["items"]
    assert len(items) == (2 if partial else 1)
    for item in items:
        detail = client.get(API + "/" + item["id"]).json()
        for record in (item, detail):
            assert record["sha256"] == data["sha256"]
            assert record["size_bytes"] == 0
            assert record["bundle_complete"] is not partial
    # A newer observation must not reuse a previous bundle's measurements.
    client.post(
        "/ingest/v1/inventory/snapshots", headers=headers(token),
        json=snapshot(data, offset=1, names=("review", "copy")),
    )
    assert all(item["size_bytes"] is None for item in client.get(API).json()["items"])


def test_skill_scores_sort_across_pages_and_keep_unknowns_last(inventory):
    st, cfg, client, token = enabled(inventory)
    snap = snapshot(bundle(), names=tuple(f"skill-{n}" for n in range(57)))
    assert (
        client.post(
            "/ingest/v1/inventory/snapshots", headers=headers(token), json=snap
        ).status_code
        == 200
    )
    for n in range(54):
        data = bundle(f"print({n})")
        upload(client, token, snap, data, f"skill-{n}")
        result = skill_scanning.validate_report(
            {**report(n == 0, complete=n != 1), "score": 25 if n == 0 else n % 4 * 25}
        )
        st.execute(
            "UPDATE skill_bundles SET status='complete',completed_at=now(),report=$3 WHERE tenant_id=$1 AND sha256=$2",
            cfg.tenant_id,
            data["sha256"],
            Jsonb(result),
        )
    for order, reverse in (("risk_asc", False), ("risk_desc", True)):
        first = client.get(API, params={"sort": order}).json()
        second = client.get(
            API, params={"sort": order, "cursor": first["next_cursor"]}
        ).json()
        items = first["items"] + second["items"]
        assert len(items) == len({i["id"] for i in items}) == 57
        assert first["total"] == second["total"] == 57
        scores = [i["retained_score"] for i in items]
        assert scores[-3:] == [None] * 3
        assert scores[:-3] == sorted(scores[:-3], reverse=reverse)
        partial = next(i for i in items if i["scan_status"] == "partial")
        assert partial["retained_score"] == 25 and partial["risk_score"] is None
        assert not second["next_cursor"]
    attention = client.get(API, params={"status": "attention"}).json()
    assert len(attention["items"]) == 1 and attention["items"][0]["risk_score"] == 25
    assert client.get(API, params={"status": "assessed"}).json()["total"] == 53
    assert client.get(API, params={"status": "pending"}).json()["total"] == 4
    assert client.get(API, params={"scope": "project"}).json()["total"] == 0
    assert (
        client.get(API, params={"scope": "user", "q": "skill-0"}).json()["total"] == 1
    )
    for params in (
        {"sort": "invalid"},
        {"scope": "invalid"},
        {"status": "invalid"},
        {"sort": "risk_asc", "cursor": "risk_desc:25:abc"},
        {"sort": "risk_desc", "cursor": "risk_desc:nan:abc"},
        {"sort": "risk_desc", "cursor": "risk_desc:10000:abc"},
        {"sort": "risk_desc", "cursor": "risk_desc:0:null\x00"},
    ):
        assert client.get(API, params=params).status_code == 400
    # Stale results and failed retries retain findings but no current score.
    st.execute(
        "UPDATE skill_bundles SET completed_at=now()-interval '2 days' WHERE tenant_id=$1",
        cfg.tenant_id,
    )
    stale = client.get(API, params={"status": "attention"}).json()
    assert stale["items"][0]["scan_status"] == "stale"
    assert stale["items"][0]["risk_score"] is None
    assert stale["items"][0]["retained_score"] == 25
    assert stale["summary"]["assessed"] == 0 and stale["summary"]["incomplete"] == 54
    st.execute(
        "UPDATE skill_bundles SET status='failed' WHERE tenant_id=$1", cfg.tenant_id
    )
    failed = client.get(API, params={"status": "attention"}).json()["items"][0]
    assert failed["needs_attention"] and failed["risk_score"] is None
    assert failed["retained_score"] == 25
    assert client.get(API + "/" + failed["id"]).json()["report"]["score"] == 25


def test_incomplete_location_invalidates_shared_assessment(inventory):
    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data, names=("review", "copy"))
    other = {
        **copy.deepcopy(snap["roots"][0]),
        "root": "/project",
        "scope": "project",
        "components": [snap["roots"][0]["components"].pop()],
    }
    snap["roots"].append(other)
    assert (
        client.post(
            "/ingest/v1/inventory/snapshots", headers=headers(token), json=snap
        ).status_code
        == 200
    )
    _, request = upload(client, token, snap, data)
    request["reference"].update(root="/project", key="copy/SKILL.md")
    assert (
        client.post(MANIFEST, json=request, headers=headers(token)).status_code == 200
    )
    job = claim(client, cfg, "test-v1")["job"]
    assert finish(client, cfg, job, {"report": report()}).status_code == 200
    assert client.get(API).json()["items"][0]["risk_score"] == 0
    for scope in ("user", "project"):
        assert (
            client.get(API, params={"scope": scope}).json()["items"][0]["installations"]
            == 2
        )
    st.execute(
        "UPDATE inventory_roots SET status='partial' WHERE tenant_id=$1 AND root='/project'",
        cfg.tenant_id,
    )
    listing = client.get(API).json()
    assert listing["summary"]["assessed"] == 0
    assert listing["items"][0]["scan_status"] == "partial"
    assert listing["items"][0]["risk_score"] is None
    assert listing["items"][0]["retained_score"] == 0
    detail = client.get(API + "/" + data["sha256"]).json()
    assert detail["scan_status"] == "partial" and detail["report"]["score"] == 0


def test_inventory_service_uploads_only_after_backend_enablement(
    inventory, tmp_path, monkeypatch
):
    from openaidr.sensor import inventory_service
    from openaidr.sensor.config import Config

    _, cfg, client, token = enabled(inventory)
    data = bundle()
    skill = tmp_path / "review"
    skill.mkdir()
    for name, encoded in data["files"].items():
        path = skill / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(encoded))
    snap = snapshot(data)
    snap["roots"][0]["components"][0]["path"] = str(skill / "SKILL.md")
    monkeypatch.setattr(inventory_service.sys, "platform", "darwin")
    monkeypatch.setattr(
        inventory_service.component_inventory, "collect_inventory", lambda *a, **k: snap
    )
    calls = []

    class SensorClient:
        def post(self, path, body):
            calls.append(path)
            reply = client.post("/ingest/v1/" + path, json=body, headers=headers(token))
            reply.raise_for_status()
            return reply.json()

    config = Config(
        tmp_path / "sensor.yaml",
        server_url="https://tenant.example",
        sensor_id=inventory[3][0][0]["id"],
        data_dir=str(tmp_path / "data"),
    )
    config["inventory"] = {"components": {"include_default_roots": False}}
    service = inventory_service.InventoryService(
        config, SensorClient(), components=True
    )
    service.sync_once()
    assert calls == [
        "inventory/snapshots",
        "inventory/skills/manifest",
        "inventory/skills/content",
    ]
    calls.clear()
    service.sync_once()
    assert not calls
    assert service.state["bundles_sent"]
    # Explicit client opt-out still sends inventory metadata, without bundle contents.
    config["inventory"]["upload_skill_bundles"] = False
    config["data_dir"] = str(tmp_path / "optout")
    inventory_service.InventoryService(
        config, SensorClient(), components=True
    ).sync_once()
    assert calls == ["inventory/snapshots"]
    calls.clear()
    cfg.skill_scanner_token = ""
    config["inventory"]["upload_skill_bundles"] = True
    config["data_dir"] = str(tmp_path / "disabled")
    inventory_service.InventoryService(
        config, SensorClient(), components=True
    ).sync_once()
    assert calls == ["inventory/snapshots"]


@pytest.mark.parametrize("invalid_answer", [False, True])
def test_llm_pilot_controls_metering_and_dedup(inventory, model_service, monkeypatch, invalid_answer):

    st, cfg, client, token = enabled(inventory)
    tenant = cfg.tenant_id
    model_service.connection_origin, model_service.connection_key = cfg.intelligence_origin, cfg.intelligence_api_key
    st.update_user(tenant, st.scalar("SELECT id FROM tenant_users WHERE tenant_id=$1", tenant), roles=["security_analyst"])
    cfg.intelligence_origin, cfg.intelligence_api_key = model_service.connection_origin, model_service.connection_key
    control = API + "/llm"
    csrf = {"X-OpenAIDR-CSRF": "1"}
    worker_headers = headers(cfg.skill_scanner_token)
    settings = {"mode": "pilot"}
    assert client.get(control).json()["mode"] == "off"
    assert client.put(control, headers=csrf, json=settings).status_code == 403
    user = st.scalar("SELECT id FROM tenant_users WHERE tenant_id=$1", tenant)
    st.update_user(tenant, user, roles=["it_admin"])
    assert client.put(control, headers=csrf, json=settings).status_code == 409
    capable = {"profile": "static-v1", "llm_profile": "luna-metered-1", "model_protocol": PROTOCOL}
    assert client.post(WORKER + "claim", headers=worker_headers, json=capable).json() == {"job": None}
    cfg.intelligence_origin = cfg.intelligence_api_key = ""
    assert client.put(control, headers=csrf, json=settings).status_code == 409
    cfg.intelligence_origin, cfg.intelligence_api_key = model_service.connection_origin, model_service.connection_key
    empty = client.put(control, headers=csrf, json=settings)
    assert empty.status_code == 409 and "No eligible" in empty.text
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    started = client.put(control, headers=csrf, json=settings)
    assert started.status_code == 200, started.text
    assert started.json()["pending"] == 1
    assert client.put(control, headers=csrf, json=settings).json()["pending"] == 1
    job = client.post(WORKER + "claim", headers=worker_headers, json=capable).json()["job"]
    assert job["llm"]
    assert client.post(WORKER + "model-call", headers=worker_headers, json={
        "sha256": job["sha256"], "lease_id": job["lease_id"], "model": "gpt-6-luna",
    }).status_code == 409
    assert st.scalar("SELECT count(*) FROM model_usage") == 0
    model_service.service.provider.invalid = invalid_answer
    request = typed_task(job)
    assert client.post(WORKER + "inference", headers=headers("bad"), json=request).status_code == 401
    assert client.post(WORKER + "inference", headers=worker_headers, json={**request, "lease_id": str(__import__('uuid').uuid4())}).status_code == 409
    for patch in ({"model": "gpt-6-astra"}, {"stream": True}, {"request": {"messages": []}}):
        assert client.post(WORKER + "inference", headers=worker_headers, json={**request, **patch}).status_code == 400
    assert not model_service.transport.requests
    reply = client.post(WORKER + "inference", headers=worker_headers, json=request)
    assert reply.status_code == 200, reply.text
    assert reply.json()["status"] == ("error" if invalid_answer else "completed")
    usage = client.get(control).json()
    assert not {"measured_usd", "reserved_usd", "remaining_usd", "budget_usd", "model"}.intersection(usage)
    assert st.scalar("SELECT budget_usd FROM tenant_skill_llm_settings WHERE tenant_id=$1", tenant) == 5
    measured = skill_llm.totals(st, tenant)
    assert float(measured["measured_usd"]) == pytest.approx(0.00002)
    assert float(measured["reserved_usd"]) == 0 and measured["calls"] == 1
    retained = st.one("SELECT * FROM model_usage WHERE tenant_id=$1", tenant)
    assert "private-skill-sentinel" not in json.dumps(retained, default=str)
    assert retained["purpose"] == "asset_management"
    assert retained["status"] == ("error" if invalid_answer else "completed")
    assert client.put(control, headers=csrf, json={"mode": "off", "budget_usd": 5}).status_code == 200
    assert client.post(WORKER + "inference", headers=worker_headers, json=request).status_code == 409
    assert len(model_service.transport.requests) == 1
    result = report()
    result.update(mode="llm", model="gpt-6-luna")
    assert finish(client, cfg, job, {"report": result}).status_code == 200
    assert st.scalar("SELECT status FROM skill_llm_jobs WHERE tenant_id=$1", tenant) == "complete"
    st.execute("UPDATE skill_bundles SET completed_at=now()-interval '2 days' WHERE tenant_id=$1", tenant)
    assert client.get(API).json()["items"][0]["scan_status"] == "complete"
    assert client.put(control, headers=csrf, json={"mode": "automatic", "budget_usd": 5}).status_code == 200
    assert client.post(WORKER + "claim", headers=worker_headers, json=capable).json()["job"] is None
    assert upload(client, token, snap, data, content=False)[0]["needs_content"] is False
    assert st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1", tenant) == 1
    assessed_at = st.scalar("SELECT completed_at FROM skill_llm_jobs WHERE tenant_id=$1", tenant)
    st.execute("DELETE FROM skill_installations WHERE tenant_id=$1", tenant)
    st.execute("DELETE FROM skill_bundles WHERE tenant_id=$1", tenant)
    upload(client, token, snap, data)
    assert client.post(WORKER + "claim", headers=worker_headers, json=capable).json()["job"] is None
    restored = st.one("SELECT report,completed_at FROM skill_bundles WHERE tenant_id=$1", tenant)
    assert restored["report"]["model"] == "gpt-6-luna" and restored["completed_at"] == assessed_at
    assert st.scalar("SELECT count(*) FROM audit_log WHERE action='skill_scanning.llm.configure' AND tenant_id=$1", tenant) == 4


def test_llm_budget_reservations_survive_failure(inventory, model_service, monkeypatch):
    from openaidr.server import skill_llm
    import httpx

    st, cfg, client, token = enabled(inventory)
    tenant = cfg.tenant_id
    st.update_user(tenant, st.scalar("SELECT id FROM tenant_users WHERE tenant_id=$1", tenant), roles=["it_admin"])
    worker_headers = headers(cfg.skill_scanner_token)
    capable = {"profile": "static-v1", "llm_profile": "luna-metered-1", "model_protocol": PROTOCOL}
    client.post(WORKER + "claim", headers=worker_headers, json=capable)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    response = client.put(API + "/llm", headers={"X-OpenAIDR-CSRF": "1"}, json={"mode": "pilot", "budget_usd": "0.02"})
    assert response.status_code == 200, response.text
    job = client.post(WORKER + "claim", headers=worker_headers, json=capable).json()["job"]
    from concurrent.futures import ThreadPoolExecutor
    import threading

    calls, admitted, release = [], threading.Event(), threading.Event()
    def unavailable(*args, **kwargs):
        calls.append(True)
        admitted.set()
        assert release.wait(10)
        raise httpx.ConnectError("private-provider-error")
    monkeypatch.setattr(skill_llm.SyncIntelligenceClient, "from_connection", unavailable)
    request = typed_task(job)
    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(client.post, WORKER + "inference", headers=worker_headers, json=request)
        try:
            assert admitted.wait(10)
            assert client.post(WORKER + "inference", headers=worker_headers, json=request).status_code == 429
        finally:
            release.set()
        first = running.result()
    assert first.status_code == 502 and "private-provider-error" not in first.text
    usage = client.get(API + "/llm").json()
    assert usage["budget_blocked"] and "reserved_usd" not in usage
    retained_usage = skill_llm.totals(st, tenant)
    assert retained_usage["unpriced_calls"] == 1 and float(retained_usage["reserved_usd"]) > 0.005
    assert client.post(WORKER + "inference", headers=worker_headers, json=request).status_code == 429
    assert len(calls) == 1
    assert st.scalar("SELECT cost_usd FROM model_usage WHERE tenant_id=$1", tenant) is None


def test_llm_pilot_limits_and_new_hash_scheduling(inventory, model_service):
    st, cfg, client, token = enabled(inventory)
    tenant = cfg.tenant_id
    st.update_user(tenant, st.scalar("SELECT id FROM tenant_users WHERE tenant_id=$1", tenant), roles=["it_admin"])
    capable = {"profile": "static-v1", "llm_profile": "luna-metered-1", "model_protocol": PROTOCOL}
    worker_headers = headers(cfg.skill_scanner_token)
    def worker_claim():
        reply = client.post(WORKER + "claim", headers=worker_headers, json=capable)
        assert reply.status_code == 200, reply.text
        return reply.json()["job"]
    def configure(mode):
        reply = client.put(API + "/llm", headers={"X-OpenAIDR-CSRF": "1"}, json={"mode": mode, "budget_usd": 5})
        assert reply.status_code == 200, reply.text
        return reply.json()
    assert worker_claim() is None
    data = bundle()
    names = tuple("skill-" + str(n) for n in range(7))
    snap = snapshot(data, names=names)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    bundles = []
    for number, name in enumerate(names):
        variant = bundle("print(" + str(number) + ")")
        upload(client, token, snap, variant, name=name)
        bundles.append(variant)
        job = worker_claim()
        assert not job.get("llm")
        assert finish(client, cfg, job, {"report": report()}).status_code == 200
    assert configure("pilot")["pending"] == 5
    assert configure("pilot")["pending"] == 5
    assert configure("off")["pending"] == 0
    configure("automatic")
    assert worker_claim() is None
    assert client.get(API + "/llm").json()["pending"] == 7
    assert configure("pilot")["pending"] == 5
    # A fresh static assessment must not suppress the upload needed for the pilot.
    target = st.scalar("SELECT sha256 FROM skill_llm_jobs WHERE tenant_id=$1 AND status='pending' LIMIT 1", tenant)
    number = next(i for i, item in enumerate(bundles) if item["sha256"] == target)
    assert upload(client, token, snap, bundles[number], name=names[number], content=False)[0]["needs_content"]
    upload(client, token, snap, bundles[number], name=names[number])
    job = worker_claim()
    assert job["llm"]
    assert finish(client, cfg, job, {"error": "timeout"}).status_code == 200
    configure("off")
    configure("automatic")
    worker_claim()
    assert st.scalar("SELECT count(*) FROM skill_llm_jobs WHERE tenant_id=$1 AND sha256=$2", tenant, target) == 1
    assert st.scalar("SELECT status FROM skill_llm_jobs WHERE tenant_id=$1 AND sha256=$2", tenant, target) == "failed"
    target = st.scalar("SELECT sha256 FROM skill_llm_jobs WHERE tenant_id=$1 AND status='pending' LIMIT 1", tenant)
    number = next(i for i, item in enumerate(bundles) if item["sha256"] == target)
    upload(client, token, snap, bundles[number], name=names[number])
    job = worker_claim()
    assert job["llm"]
    assert finish(client, cfg, job, {"report": report()}).status_code == 200
    st.execute("UPDATE skill_bundles SET completed_at=now()-interval '2 days' WHERE tenant_id=$1 AND sha256=$2", tenant, target)
    worker_claim()
    retained = st.one("SELECT status,report FROM skill_bundles WHERE tenant_id=$1 AND sha256=$2", tenant, target)
    assert retained["status"] == "awaiting_upload" and not retained["report"].get("llm_cache")


def test_legacy_model_call_authorization_expiry_and_idempotent_completion(inventory):
    from openaidr.server.service_costs import chat_usage
    from decimal import Decimal

    st, cfg, client, token = enabled(inventory)
    data = bundle()
    snap = snapshot(data)
    client.post("/ingest/v1/inventory/snapshots", headers=headers(token), json=snap)
    upload(client, token, snap, data)
    job = claim(client, cfg)["job"]
    request = {"sha256": job["sha256"], "lease_id": job["lease_id"], "model": "gpt-6-luna"}
    endpoint, auth = WORKER + "model-call", headers(cfg.skill_scanner_token)
    assert client.post(endpoint, json=request, headers=headers(token)).status_code == 401
    assert client.post(endpoint, json=request, headers=auth).status_code == 409
    # A pending record from an older worker remains settleable after the cutover.
    from openaidr.server.service_costs import Call
    call = Call(st, cfg.tenant_id, "asset_management", "openai", MODEL)
    usage_id = call.id
    st.execute("UPDATE model_usage SET skill_scan_lease_id=$2 WHERE id=$1", usage_id, job["lease_id"])
    st.execute("UPDATE skill_bundles SET lease_until=now()-interval '1 second'")
    assert client.post(endpoint, json=request, headers=auth).status_code == 409
    completion = {"lease_id": job["lease_id"], "usage_id": usage_id, "failed": False,
                  "response": chat_usage({"model": "gpt-6-luna", "service_tier": "default", "usage": {
                      "prompt_tokens": 1000, "completion_tokens": 200,
                      "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}})}
    assert client.post(endpoint, json={**completion, "lease_id": str(__import__('uuid').uuid4())}, headers=auth).status_code == 404
    assert client.post(endpoint, json=completion, headers=auth).json() == {"accepted": True}
    row = st.one("SELECT * FROM model_usage")
    assert row["cost_usd"] == Decimal(".0002")
    assert client.post(endpoint, json={**completion, "failed": True, "response": {}}, headers=auth).status_code == 200
    assert st.one("SELECT * FROM model_usage") == row
    cfg.tenant_id = inventory[3][1][0]["tenant_id"]
    assert client.post(endpoint, json=completion, headers=auth).status_code == 404
