"""Exceptional evidence survives storage without changing its characters or types."""

import base64
import json
import math
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from openaidr.server import auth, ingest_evidence as evidence, telemetry_retention
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.store import Conflict, new_id
from test_store import db as db, sensor, tenant


@pytest.mark.parametrize("value,reason", [
    ({"text": "nul\x00"}, "nul_character"),
    ({"nul\x00": "value"}, "nul_character"),
    ({"text": "\ud800"}, "unpaired_surrogate"),
    ({"\udfff": "value"}, "unpaired_surrogate"),
    ({"text": "😀 中文 café\n\t\u001b\ufdd0\uffff"}, ""),
    ({"text": r"\u0000"}, ""),
    ({"values": [True, None, 23, -1.5]}, ""),
    ({"number": float("inf")}, "nonfinite_number"),
    ({"number": float("nan")}, "nonfinite_number"),
])
def test_storage_validation_and_lossless_codec(value, reason):
    assert evidence.storage_issue(value) == reason
    raw = evidence.encode(value)
    assert raw.isascii() and b"\x00" not in raw
    restored = evidence.loads(raw)
    if math.isnan(value.get("number", 0)):
        assert math.isnan(restored["number"])
    else:
        assert restored == value


def test_number_tokens_and_deep_evidence_remain_recoverable():
    for token in ("1e200000", "-1e-200000", "1e-99999999999999999999", "9" * 4500):
        value = evidence.loads('{"value":' + token + '}')
        assert evidence.storage_issue(value) == "unsupported_number"
        assert evidence.encode(value) == ('{"value":' + token + '}').encode()
    value = {"secret": "\x00"}
    for _ in range(200):
        value = [value]
    assert evidence.storage_issue(value) == "nesting_limit"
    assert evidence.loads(evidence.encode(value)) == value
    with pytest.raises(ValueError):
        evidence.loads(b'{"invalid":"\xff"}')


def test_postgres_retention_identity_transaction_and_migration(db):
    own, other = tenant(db), tenant(db)
    device = sensor(db, own["id"])[0]
    value = {"tool": {"output": "PDF\x00\ud800"}, "literal": r"\u0000"}
    key = new_id()
    row = evidence.retain(db, device, "events", key, value, "nul_character")
    assert row["status"] == "unavailable"
    assert evidence.retain(db, device, "events", key, value, "nul_character") == row
    assert evidence.loads(evidence.read(db, own["id"], row["id"])["payload"]) == value
    with pytest.raises(Conflict):
        evidence.retain(db, device, "events", key, {"different": True}, "nul_character")
    with pytest.raises(Conflict):
        evidence.retain(db, {**device, "tenant_id": other["id"]}, "events", new_id(), value, "nul_character")
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            evidence.retain(db, device, "events", new_id(), value, "nul_character", conn=conn)
            raise RuntimeError("source write failed")
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    db.execute("DELETE FROM sensors WHERE id=$1", device["id"])
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
    db.execute("DROP TABLE retained_ingest_evidence")
    db.execute("DELETE FROM schema_migrations WHERE version=73")
    assert db.migrate() == ["0073_retained_ingest_evidence.sql"]
    assert db.migrate() == []


def test_retained_evidence_api_permissions_pagination_and_download(db):
    own, other = tenant(db), tenant(db)
    device = sensor(db, own["id"])[0]
    headers = {}
    for role, organization in (("viewer", own), ("analyst", own), ("foreign", other)):
        user = db.create_user(organization["id"], role + "@example.test", role, "hash",
                              "analyst" if role == "foreign" else role)
        headers[role] = {"Cookie": auth.CONSOLE_COOKIE + "=" + db.create_session(user["id"], organization["id"])}
    value = {"nested": [{"\x00": "original\ud800"}], "valid": "中文"}
    records = [evidence.retain(db, device, "events", new_id(), value, "nul_character") for _ in range(2)]
    cfg = Config(database_url=db.url)
    cfg.set_services("api")
    with TestClient(create_app(cfg, db)) as client:
        path = "/api/v1/ingestion/retained-records"
        assert client.get(path).status_code == 401
        assert client.get(path, headers=headers["viewer"]).status_code == 403
        first = client.get(path + "?limit=1", headers=headers["analyst"])
        assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
        assert len(first.json()["items"]) == 1 and first.json()["next_cursor"]
        assert "payload" not in first.json()["items"][0]
        second = client.get(path, params={"limit": 1, "cursor": first.json()["next_cursor"]}, headers=headers["analyst"])
        assert first.json()["items"][0]["id"] != second.json()["items"][0]["id"]
        item = path + "/" + records[0]["id"]
        assert client.get(item, headers=headers["viewer"]).status_code == 403
        assert client.get(item + "/download", headers=headers["viewer"]).status_code == 403
        assert client.get(item, headers=headers["foreign"]).status_code == 404
        assert client.get(item + "/download", headers=headers["foreign"]).status_code == 404
        assert client.get(path, headers=headers["foreign"]).json()["items"] == []
        detail = client.get(item, headers=headers["analyst"])
        raw = base64.b64decode(detail.json()["payload_base64"])
        assert evidence.loads(raw) == value
        download = client.get(item + "/download", headers=headers["analyst"])
        assert download.content == raw and download.headers["cache-control"] == "no-store"
        assert download.headers["content-type"] == "application/octet-stream"
        assert db.scalar("SELECT count(*) FROM audit_log WHERE action='ingestion_evidence.read'") == 2


def test_retained_evidence_obeys_tenant_retention(db):
    own, other = tenant(db), tenant(db)
    devices = [sensor(db, organization["id"])[0] for organization in (own, other)]
    for device in devices:
        evidence.retain(db, device, "events", new_id(), {"value": "\x00"}, "nul_character")
    db.execute("UPDATE retained_ingest_evidence SET received_at=now()-interval '8 days'")
    cfg = SimpleNamespace(tenant_id=own["id"], telemetry_retention_disk_path="", host_metrics_path="")
    telemetry_retention.tick(db, cfg)
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 2
    telemetry_retention.save_settings(db, own["id"], {"mode": "7", "version": 0}, {}, cfg)
    telemetry_retention.tick(db, cfg)
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    assert db.scalar("SELECT tenant_id FROM retained_ingest_evidence") == other["id"]


@pytest.mark.parametrize("zone", ["America/Los_Angeles", "Asia/Tokyo"])
def test_pressure_retention_uses_utc_days_in_any_session_timezone(db, zone):
    own = tenant(db)
    device = sensor(db, own["id"])[0]
    rows = [evidence.retain(db, device, "events", new_id(), {"value": "\x00"}, "nul_character") for _ in range(2)]
    for row, stamp in zip(rows, ("2026-10-11T23:30:00Z", "2026-10-12T00:30:00Z")):
        db.execute("UPDATE retained_ingest_evidence SET received_at=$2::timestamptz WHERE id=$1", row["id"], stamp)
    db.execute("""INSERT INTO tenant_telemetry_retention
        (tenant_id,mode,cleanup_threshold_percent,last_deleted_day) VALUES($1,'unlimited',80,'2026-10-11')""", own["id"])
    with db.transaction() as conn:
        db.scalar("SELECT set_config('TimeZone',$1,true)", zone, conn=conn)
        assert evidence.cleanup(db, own["id"], conn) == 1
    assert db.scalar("SELECT id FROM retained_ingest_evidence") == rows[1]["id"]


def test_locked_evidence_cleanup_does_not_block_telemetry_retirement(db):
    from test_telemetry_retention import seed

    own = tenant(db)
    device = sensor(db, own["id"])[0]
    row = evidence.retain(db, device, "events", new_id(), {"value": "\x00"}, "nul_character")
    db.execute("UPDATE retained_ingest_evidence SET received_at=now()-interval '8 days'")
    event_id, day = seed(db, device, 8)
    cfg = SimpleNamespace(tenant_id=own["id"], telemetry_retention_disk_path="", host_metrics_path="")
    telemetry_retention.save_settings(db, own["id"], {"mode": "7", "version": 0}, {}, cfg)
    with db.transaction() as blocker:
        db.execute("SELECT id FROM retained_ingest_evidence WHERE id=$1 FOR UPDATE", row["id"], conn=blocker)
        telemetry_retention.tick(db, cfg)
        assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
        assert not db.scalar("SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)", event_id)
        assert db.scalar("SELECT retired_at IS NOT NULL FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2",
                         own["id"], day)
    telemetry_retention.tick(db, cfg)
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
