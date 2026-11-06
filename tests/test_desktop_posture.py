"""Desktop inventory uses real PostgreSQL and sensor authentication."""

import json
from datetime import datetime, timedelta

from psycopg.types.json import Jsonb

from openaidr.server import app_inventory, component_inventory, desktop_posture
from openaidr.server.store import now
from test_app_inventory_server import inventory  # noqa: F401

ENDPOINT = "/ingest/v1/posture/summary"


def app(st, sensor, name="Cursor"):
    stamp = now() - timedelta(hours=2)
    app_inventory.ingest_snapshot(st, sensor, {
        "schema_version": 1, "platform": "linux", "collected_at": stamp.isoformat(),
        "sources": [{"source": "linux-desktop", "status": "ok", "message": ""}],
        "applications": [{"source": "linux-desktop", "identifier": name.lower(), "name": name,
                          "version": "1", "path": "/apps/" + name, "kind": "application", "scope": "user"}],
    })
    return stamp


def components(st, sensor, *, count=1, long_names=False):
    roots = []
    for source, kind in (("openaidr-mcp-servers", "mcp_server"), ("openaidr-skills", "skill"),
                         ("osquery-npm-packages", "package")):
        root = "/" + source
        rows = [{"key": str(index), "identifier": "example" if kind == "package" else str(index),
                 "name": f"{kind}-{index:04d}", "kind": kind, "ecosystem": "npm" if kind == "package" else "",
                 "path": root + "/" + ("x" * 7000 if long_names else "entry") + str(index),
                 "version": "1.0.0", "evidence": "configured" if kind == "mcp_server" else "installed",
                 "metadata": {"description": "Retained description <script>evidence</script>"}}
                for index in range(count)]
        roots.append(dict(source=source, root=root, scope="user", status="ok", message="",
                          components=rows, relationships=[]))
    component_inventory.ingest_snapshot(st, sensor, {
        "schema_version": 1, "platform": "linux", "collected_at": now().isoformat(), "roots": roots,
    })


def read(client, token):
    result = client.post(ENDPOINT, json={}, headers={"Authorization": "Bearer " + token})
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    return result.json()


def test_posture_binds_device_and_tenant_and_rejects_invalid_requests(inventory):
    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    foreign = identities[1][0]
    headers = {"Authorization": "Bearer " + token}
    enrollment = st.create_enrollment_token(sensor["tenant_id"])
    peer, _, _ = st.enroll_sensor({"enrollment_token": enrollment["token"], "hostname": "private-peer"})
    own_stamp = app(st, sensor)
    app(st, peer, "ChatGPT")
    app(st, foreign, "Claude")
    for device in (sensor, peer, foreign):
        components(st, device)
    assert client.post(ENDPOINT, json={}).status_code == 401
    for body in ({"sensor_id": peer["id"]}, {"tenant_id": foreign["tenant_id"]}, {"limit": 1}, [], True):
        assert client.post(ENDPOINT, json=body, headers=headers).status_code == 400
    assert client.post(ENDPOINT, content="{", headers=headers).status_code == 400
    assert client.post(ENDPOINT, content='{"padding":"' + "x" * 1024 + '"}', headers=headers).status_code == 413
    result = read(client, token)
    assert result["schema_version"] == 1
    assert datetime.fromisoformat(result["collected_at"]) == own_stamp
    assert {key: value["total"] for key, value in result["groups"].items()} == dict(apps=1, components=2, skills=1)
    assert result["groups"]["apps"]["items"][0]["product"] == "cursor"
    all_items = [item for group in result["groups"].values() for item in group["items"]]
    expected_ids = {row["id"] for row in st.many("SELECT id FROM inventory_components WHERE sensor_id=$1", sensor["id"])}
    assert {item["id"] for item in all_items if item["kind"] != "application"} == expected_ids
    assert "private-peer" not in json.dumps(result) and "ChatGPT" not in json.dumps(result) and '"Claude"' not in json.dumps(result)
    assert all("sensor_id" not in row and "manifest" not in row and "report" not in row for row in all_items)
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=True)
    assert client.post(ENDPOINT, json={}, headers=headers).status_code == 403
    st.update_sensor(sensor["tenant_id"], sensor["id"], disabled=False)
    st.delete_sensor(sensor["tenant_id"], sensor["id"])
    assert client.post(ENDPOINT, json={}, headers=headers).status_code == 401


def test_posture_preserves_unknown_assessments_approvals_and_partial_coverage(inventory):
    st, cfg, client, identities = inventory
    sensor, token, _ = identities[0]
    empty = read(client, token)
    assert empty["coverage"] == {"status": "unavailable", "sources": []} and empty["collected_at"] is None
    app(st, sensor)
    components(st, sensor)
    first = read(client, token)
    assert first["coverage"]["status"] == "complete"
    skill = first["groups"]["skills"]["items"][0]
    assert skill["approval_status"] == "unavailable" and skill["assessment_status"] == "disabled"
    kinds = {row["kind"]: row for row in first["groups"]["components"]["items"]}
    assert kinds["mcp_server"]["assessment_status"] == "unsupported" and kinds["mcp_server"]["findings"] == []
    assert kinds["package"]["assessment_status"] == "pending"
    assert first["groups"]["apps"]["items"][0]["approval_status"] == "unapproved"
    st.execute("INSERT INTO ai_application_approvals(tenant_id,product_id,name,approved) VALUES($1,'cursor','Cursor',NULL)", sensor["tenant_id"])
    assert read(client, token)["groups"]["apps"]["items"][0]["approval_status"] == "monitoring"
    st.execute("UPDATE ai_application_approvals SET approved=true WHERE tenant_id=$1", sensor["tenant_id"])
    assert read(client, token)["groups"]["apps"]["items"][0]["approval_status"] == "approved"
    stamp = st.scalar("SELECT last_seen_at FROM inventory_components WHERE id=$1", skill["id"])
    sha = "a" * 64
    report = {"complete": True, "needs_attention": True, "issues": [{"title": "Review literal evidence",
              "description": "Preserve quoted evidence exactly."}], "private_provider": "PRIVATE-PROVIDER"}
    st.execute("""INSERT INTO skill_bundles(tenant_id,sha256,manifest,content_bytes,status,report,completed_at)
        VALUES($1,$2,$3,10,'complete',$4,now())""", sensor["tenant_id"], sha,
        Jsonb({"complete": True, "private_manifest": "PRIVATE-MANIFEST"}), Jsonb(report))
    st.execute("""INSERT INTO skill_installations(component_id,tenant_id,sensor_id,sha256,observed_at)
        VALUES($1,$2,$3,$4,$5)""", skill["id"], sensor["tenant_id"], sensor["id"], sha, stamp)
    st.execute("INSERT INTO skill_reviews(tenant_id,skill_id,sha256,approved) VALUES($1,$2,$2,true)", sensor["tenant_id"], sha)
    cfg.skill_scanner_token = "synthetic-enabled-scanner"
    assessed = read(client, token)
    installed = assessed["groups"]["skills"]["items"][0]
    assert installed["assessment_status"] == "complete" and installed["approval_status"] == "approved" and installed["attention"]
    assert installed["findings"] == [{"title": "Review literal evidence", "detail": "Preserve quoted evidence exactly."}]
    assert "PRIVATE-" not in json.dumps(assessed)
    st.execute("UPDATE inventory_roots SET status='partial' WHERE sensor_id=$1 AND source='openaidr-skills'", sensor["id"])
    partial = read(client, token)
    assert partial["coverage"]["status"] == "partial"
    assert partial["groups"]["skills"]["items"][0]["assessment_status"] == "partial"
    st.execute("UPDATE inventory_components SET last_seen_at=last_seen_at+interval '1 second' WHERE id=$1", skill["id"])
    changed = read(client, token)["groups"]["skills"]["items"][0]
    assert changed["approval_status"] == "unavailable" and changed["assessment_status"] == "pending" and changed["findings"] == []
    st.execute("""INSERT INTO inventory_osv_packages(tenant_id,ecosystem,identifier,version,
        checked_at,next_check_at,findings) VALUES($1,'npm','example','1.0.0',now(),now(),$2)""",
        sensor["tenant_id"], Jsonb([{"id": "CVE-2026-1234", "summary": "Retained package finding"}]))
    package = next(row for row in read(client, token)["groups"]["components"]["items"] if row["kind"] == "package")
    assert package["assessment_status"] == "complete" and package["attention"]
    assert package["findings"] == [{"title": "CVE-2026-1234", "detail": "Retained package finding"}]
    st.execute("UPDATE inventory_osv_packages SET error='Upstream assessment unavailable' WHERE tenant_id=$1", sensor["tenant_id"])
    failed = next(row for row in read(client, token)["groups"]["components"]["items"] if row["kind"] == "package")
    assert failed["assessment_status"] == "failed" and failed["findings"] == package["findings"]
    cfg.osv_assessment = False
    assert {row["assessment_status"] for row in read(client, token)["groups"]["components"]["items"]} == {"disabled"}


def test_posture_bounds_rows_and_encoded_response_without_cutting_evidence(inventory):
    st, _, client, identities = inventory
    sensor, token, _ = identities[0]
    components(st, sensor, count=205, long_names=True)
    result = read(client, token)
    assert result["groups"]["components"]["total"] == 410 and result["groups"]["skills"]["total"] == 205
    assert result["groups"]["components"]["truncated"] and result["groups"]["skills"]["truncated"]
    assert len(json.dumps(result, ensure_ascii=True).encode()) <= desktop_posture.MAX_BYTES
    for group in (result["groups"]["components"], result["groups"]["skills"]):
        assert 0 < len(group["items"]) < 200
        assert all("x" * 7000 in row["path"] for row in group["items"])
