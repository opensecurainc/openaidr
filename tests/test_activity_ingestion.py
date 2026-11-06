"""Mixed activity batches remain durable through PostgreSQL and HTTP failures."""

import base64
import hashlib

import psycopg

from fastapi.testclient import TestClient
import pytest

from openaidr.core.event import new_id, now
from openaidr.server import ingest_evidence as evidence
from openaidr.server.app import create_app
from openaidr.server.config import Config
from test_store import db as db, sensor, tenant

PATH = "/ingest/v1/events"


@pytest.fixture
def activity(db):
    own = tenant(db)
    device, token, _ = sensor(db, own["id"])
    cfg = Config(database_url=db.url)
    cfg.set_services("ingest")
    with TestClient(create_app(cfg, db)) as client:
        yield db, device, client, {"Authorization": "Bearer " + token}


def event(**extra):
    return {"id": new_id(), "time": now(), "kind": "tool.result", "agent": {"product": "claude-code"},
            "session": {"id": "session"}, "tool": {"name": "Bash", "output": "done"}, **extra}


def post(activity, events):
    _, _, client, headers = activity
    return client.post(PATH, content=evidence.encode({"events": events}), headers=headers)


def test_mixed_batch_retains_unsupported_evidence_and_retries_without_duplicates(activity):
    db, device, client, headers = activity
    good = event(tool={"name": "Bash", "output": "😀 中文 café\n\t\u001b " + r"\u0000"})
    bad = [
        event(tool={"name": "Bash", "output": "%PDF\x00"}),
        event(kind="command", command={"text": "echo\x00test"}),
        event(agent={"product": "claude\x00code"}),
        event(raw={"\ud800": "unpaired key", "nested": [{"value": "\udfff"}]}),
        event(raw={"number": evidence.Number("1e200000")}),
        event(raw={"number": float("nan")}),
        event(session={"id": 123}),
        event(source={"hook_request_id": 123}),
        event(tool={"call_id": {"invalid": "identity"}}),
        event(time="not a timestamp"),
        {},
    ]
    original = [evidence.encode(value) for value in bad]
    batch = [good, *bad, event(kind="session.end")]
    result = post(activity, batch)
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["accepted"] == 2 and result["duplicates"] == 0
    assert [item["index"] for item in result["rejected"]] == list(range(1, len(bad) + 1))
    for rejected, raw in zip(result["rejected"], original):
        assert evidence.read(db, device["tenant_id"], rejected["retained_id"])["payload"] == raw
    assert db.get_event(device["tenant_id"], good["id"])["body"]["tool"] == good["tool"]
    assert db.scalar("SELECT events_total FROM sensor_activity WHERE sensor_id=$1", device["id"]) == 2
    retry = post(activity, batch).json()
    assert retry["accepted"] == 0 and retry["duplicates"] == 2
    assert retry["rejected"] == result["rejected"]
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == len(bad)
    assert db.scalar("SELECT count(*) FROM events") == 2
    # Authentication and disabled-state checks run before any fallback retention.
    raw = evidence.encode({"events": bad})
    assert client.post(PATH, content=raw).status_code == 401
    db.execute("UPDATE sensors SET disabled=true WHERE id=$1", device["id"])
    assert client.post(PATH, content=raw, headers=headers).status_code == 403
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == len(bad)


def test_invalid_wire_bytes_and_batch_shapes_are_retained_before_acknowledgment(activity):
    db, device, client, headers = activity
    for raw in (b'{"events":[{"output":"\xff"}]}', b'{"events":[', b'{"events":"invalid"}', b'[]'):
        result = client.post(PATH, content=raw, headers=headers)
        assert result.status_code == 200, result.text
        rejected = result.json()["rejected"][0]
        retained = evidence.loads(evidence.read(db, device["tenant_id"], rejected["retained_id"])["payload"])
        if rejected["reason"] == "invalid_json":
            assert base64.b64decode(retained["wire_base64"]) == raw
        else:
            assert retained == evidence.loads(raw)
        assert client.post(PATH, content=raw, headers=headers).json() == result.json()
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 4
    assert client.post(PATH, json={"sensor_id": new_id(), "events": [event()]}, headers=headers).status_code == 403
    assert post(activity, [event() for _ in range(501)]).status_code == 413
    assert db.scalar("SELECT count(*) FROM events") == 0


@pytest.mark.parametrize("sqlstate", ["22003", "55P03"])
def test_database_data_errors_are_isolated_but_transient_errors_roll_back(activity, sqlstate):
    db, device, *_ = activity
    # A real database error after inventory writes verifies savepoint rollback,
    # instead of replacing the persistence implementation with a mock.
    db.execute("""CREATE FUNCTION reject_test_record() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.body->>'test_data_error'='yes' THEN
            RAISE EXCEPTION 'test database failure' USING ERRCODE='""" + sqlstate + """';
        END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_test_record BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION reject_test_record()""")
    first = event(session={"id": "first"})
    failed = event(session={"id": "failed"}, test_data_error="yes")
    unsupported = event(tool={"output": "nul\x00"})
    batch = [first, failed, unsupported, event(session={"id": "last"})]
    result = post(activity, batch)
    if sqlstate == "55P03":
        assert result.status_code == 503, result.text
        assert db.scalar("SELECT count(*) FROM events") == 0
        assert db.scalar("SELECT count(*) FROM event_keys") == 0
        assert db.scalar("SELECT count(*) FROM agents") == 0
        assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 0
        db.execute("DROP TRIGGER reject_test_record ON events")
        result = post(activity, batch)
        assert result.status_code == 200 and result.json()["accepted"] == 3
        assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    else:
        assert result.status_code == 200, result.text
        assert result.json()["accepted"] == 2
        assert [row["index"] for row in result.json()["rejected"]] == [1, 2]
        assert db.scalar("SELECT count(*) FROM events") == 2
        assert db.scalar("SELECT count(*) FROM agent_sessions") == 2
        assert db.scalar("SELECT events_total FROM agents") == 2
        assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 2
        retry = post(activity, batch).json()
        assert retry["duplicates"] == 2 and retry["accepted"] == 0
        assert retry["rejected"] == result.json()["rejected"]


@pytest.mark.parametrize("section,field", [("session", "id"), ("host", "user")])
def test_postgresql_index_limits_retain_original_records_without_blocking_neighbors(activity, section, field):
    db, device, *_ = activity
    # Deterministic, incompressible data exceeds PostgreSQL's actual btree limit.
    identity = "".join(hashlib.sha256(str(index).encode()).hexdigest() for index in range(100))
    bad = event(**{section: {field: identity}})
    with pytest.raises(psycopg.errors.ProgramLimitExceeded):
        db.ingest_batch(device, [bad])
    assert db.scalar("SELECT count(*) FROM agents") == 0
    batch = [event(session={"id": "before"}), bad, event(session={"id": "after"})]
    result = post(activity, batch)
    assert result.status_code == 200, result.text
    result = result.json()
    assert result["accepted"] == 2 and result["duplicates"] == 0
    assert len(result["rejected"]) == 1 and result["rejected"][0]["index"] == 1
    retained = evidence.read(db, device["tenant_id"], result["rejected"][0]["retained_id"])
    assert retained["payload"] == evidence.encode(bad)
    retry = post(activity, batch).json()
    assert retry["accepted"] == 0 and retry["duplicates"] == 2
    assert retry["rejected"] == result["rejected"]
    assert db.scalar("SELECT count(*) FROM retained_ingest_evidence") == 1
    assert db.scalar("SELECT count(*) FROM event_keys") == 2
    assert db.scalar("SELECT count(*) FROM agent_sessions") == 2
    assert db.scalar("SELECT count(*) FROM agents") == 1
    assert db.scalar("SELECT events_total FROM agents") == 2
    assert db.scalar("SELECT events_total FROM sensor_activity WHERE sensor_id=$1", device["id"]) == 2
