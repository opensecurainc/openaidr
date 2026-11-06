import os
import base64
import copy
import json
from datetime import timedelta
import pytest
import psycopg
from psycopg.conninfo import make_conninfo
from openaidr.server.store import (
    Store,
    Cursor,
    Page,
    decode_cursor,
    decode_live_cursor,
    new_id,
    new_token,
    hash_token,
    valid_slug,
    valid_uuid,
    now,
    NotFound,
    Conflict,
    TokenExhausted,
    TokenRevoked,
)
from openaidr.server.model import public_record


def test_identifiers_and_cursor():
    id = new_id()
    assert valid_uuid(id)
    assert id[14] == "7"
    token, hashed = new_token("oaet_")
    assert token.startswith("oaet_") and len(token) == 48
    assert hash_token(token) == hashed and len(hashed) == 64
    c = Cursor(now(), id)
    assert decode_cursor(c.encode()) == c
    assert decode_cursor("").id == ""
    for bad in ("???", "eA", "bm90LWEtdGltZXwz"):
        with pytest.raises(ValueError):
            decode_cursor(bad)
    assert Page(900).norm().limit == 500
    assert Page(-1).norm().limit == 50
    assert valid_slug("acme-inc") and not valid_slug("-bad")


@pytest.fixture
def db():
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL not configured")
    schema = "test_" + new_id().replace("-", "")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    s = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    s.migrate()
    try:
        yield s
    finally:
        s.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


def tenant(db):
    return db.create_tenant("Test tenant", "test-" + new_id(), "", [])


def sensor(db, tid):
    token = db.create_enrollment_token(tid, "test", 3600, 1)
    return db.enroll_sensor(
        {
            "enrollment_token": token["token"],
            "hostname": "host",
            "os": "linux",
            "arch": "amd64",
            "user": "alice",
        }
    )


def test_tenants_auth_and_invites(db):
    t = tenant(db)
    other = tenant(db)
    user = db.create_user(t["id"], new_id() + "@test.invalid", "Alice", "hash", "owner")
    with pytest.raises(NotFound):
        db.get_user(other["id"], user["id"])
    session = db.create_session(user["id"], t["id"])
    assert db.get_session(session)["user"]["id"] == user["id"]
    db.execute(
        "UPDATE auth_sessions SET last_seen_at=now()-interval '2 hours',expires_at=now()+interval '1 hour' WHERE token_hash=$1",
        hash_token(session),
    )
    assert db.get_session(session)["tenant"]["id"] == t["id"]
    assert db.scalar(
        "SELECT expires_at>now()+interval '29 days' FROM auth_sessions WHERE token_hash=$1",
        hash_token(session),
    )
    db.delete_session(session)
    with pytest.raises(NotFound):
        db.get_session(session)
    inv = db.create_invite(t["id"], new_id() + "@test.invalid", "viewer", ttl=3600)
    accepted = db.accept_invite(inv, "Bob", "hash")
    assert accepted["role"] == "viewer"
    with pytest.raises(NotFound):
        db.accept_invite(inv, "Bob", "hash")
    duplicate = db.create_invite(t["id"], user["email"], "viewer", ttl=3600)
    with pytest.raises(Conflict):
        db.accept_invite(duplicate, "Duplicate", "hash")
    assert db.get_invite_by_token(duplicate["token"])["accepted_at"] is None
    assert "password_hash" not in public_record(user, "user")


def test_identity_revocation_migration_preserves_existing_accounts(db):
    # This additive migration's predecessor differs only by the new empty table.
    db.execute("DROP TABLE tenant_identity_revocations")
    db.execute("DELETE FROM schema_migrations WHERE version=18")
    t = tenant(db)
    local = db.create_user(t["id"], "local@example.test", "Local", "hash", "owner")
    local_session = db.create_session(local["id"], t["id"])
    external_id, external_session = new_id(), new_token("oass_")
    db.execute(
        "INSERT INTO tenant_users(id,tenant_id,email,name,password_hash,role,oidc_issuer,oidc_subject) "
        "VALUES($1,$2,'external@example.test','External',NULL,'viewer','https://auth.example.test','subject')",
        external_id, t["id"],
    )
    db.execute(
        "INSERT INTO auth_sessions(id,token_hash,user_id,tenant_id,expires_at,oidc_issuer,verified_at) "
        "VALUES($1,$2,$3,$4,now()+interval '1 hour','https://auth.example.test',now())",
        new_id(), external_session[1], external_id, t["id"],
    )
    users = db.many("SELECT * FROM tenant_users ORDER BY id")
    sessions = db.many("SELECT * FROM auth_sessions ORDER BY id")
    assert db.migrate() == ["0018_tenant_identity_revocations.sql"]
    assert db.migrate() == []
    assert db.many("SELECT * FROM tenant_users ORDER BY id") == users
    assert db.many("SELECT * FROM auth_sessions ORDER BY id") == sessions
    assert db.get_session(local_session)["user"]["id"] == local["id"]
    assert db.get_session(external_session[0])["oidc_issuer"] == "https://auth.example.test"
    assert db.scalar("SELECT count(*) FROM tenant_identity_revocations") == 0
    db.delete_user(t["id"], local["id"])
    assert db.scalar("SELECT count(*) FROM tenant_identity_revocations") == 0


def test_migrations_release_ddl_locks_before_backfill_and_resume(db, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import time
    from openaidr.server import store

    migrations = tmp_path / "migrations"
    migrations.mkdir()
    monkeypatch.setattr(store, "__file__", str(tmp_path / "store.py"))
    db.execute("CREATE TABLE migration_probe (id int PRIMARY KEY)")
    (migrations / "9000_ddl.sql").write_text(
        "ALTER TABLE migration_probe ADD COLUMN note text"
    )
    (migrations / "9001_backfill.sql").write_text(
        "SELECT pg_advisory_xact_lock(91247321); "
        "INSERT INTO migration_probe VALUES (2,'backfill')"
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction() as gate:
            gate.execute("SELECT pg_advisory_xact_lock(91247321)")
            pending = pool.submit(db.migrate)
            deadline = time.monotonic() + 5
            while not db.scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                "AND objid=91247321 AND NOT granted)"
            ):
                assert time.monotonic() < deadline, "Backfill did not reach its gate"
                time.sleep(0.01)
            # A retained-history scan may be slow; its earlier DDL must no
            # longer block writes from the server that is still running.
            with db.transaction() as writer:
                writer.execute("SET LOCAL lock_timeout='1s'")
                writer.execute("INSERT INTO migration_probe(id) VALUES (1)")
        assert pending.result(timeout=5) == ["9000_ddl.sql", "9001_backfill.sql"]
    failing = migrations / "9002_failure.sql"
    failing.write_text("INSERT INTO migration_probe VALUES (3,'retry'); SELECT 1/0")
    with pytest.raises(psycopg.errors.DivisionByZero):
        db.migrate()
    assert db.scalar("SELECT count(*) FROM migration_probe") == 2
    assert db.scalar("SELECT count(*) FROM schema_migrations WHERE version=9002") == 0
    failing.write_text("INSERT INTO migration_probe VALUES (3,'retry')")
    assert db.migrate() == ["9002_failure.sql"]
    assert db.migrate() == []
    assert db.scalar("SELECT count(*) FROM migration_probe") == 3


@pytest.mark.parametrize("version,filename,columns", [
    (71, "0071_sensor_policy_delivery.sql", ("policy_delivery", "policy_delivery_reported_at")),
    (74, "0074_sensor_health.sql", ("health_report", "health_reported_at")),
])
def test_sensor_diagnostic_migrations_preserve_existing_sensor_state(db, version, filename, columns):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    db.record_heartbeat(s["id"], {"sensor_version": "older-sensor", "policy_version": 7})
    db.execute("ALTER TABLE sensor_activity " + ", ".join("DROP COLUMN " + name for name in columns))
    db.execute("DELETE FROM schema_migrations WHERE version=$1", version)
    before = db.one("SELECT * FROM sensor_activity WHERE sensor_id=$1", s["id"])
    assert db.migrate() == [filename]
    assert db.migrate() == []
    after = db.one("SELECT * FROM sensor_activity WHERE sensor_id=$1", s["id"])
    for name in columns:
        assert after.pop(name) is None
    assert after == before
    assert db.get_sensor(t["id"], s["id"])["policy_delivery"] is None


def test_enrollment_commands_and_policy(db):
    t = tenant(db)
    other = tenant(db)
    token = db.create_enrollment_token(t["id"], "once", 3600, 1)
    req = {"enrollment_token": token["token"], "hostname": "host"}
    s, plain, enrolled_tenant = db.enroll_sensor(req)
    assert s["status"] == "online" and enrolled_tenant["id"] == t["id"]
    assert db.get_sensor_by_token(plain)["id"] == s["id"]
    with pytest.raises(TokenExhausted):
        db.enroll_sensor(req)
    db.revoke_enrollment_token(t["id"], token["id"])
    with pytest.raises(TokenRevoked):
        db.enroll_sensor(req)
    command = db.queue_command(t["id"], s["id"], "disable", {})
    assert db.pending_commands(s["id"])[0]["id"] == command
    db.ack_command(s["id"], command, {"status": "applied"})
    assert db.pending_commands(s["id"]) == []
    hook = db.queue_command(t["id"], s["id"], "install_hook", {"agent": "codex"})
    queued = db.get_command(t["id"], s["id"], hook)
    assert queued["status"] == "pending" and queued["params"] == {"agent": "codex"}
    assert queued["delivered_at"] is None and queued["message"] == ""
    # Opposite commands queued before one heartbeat are delivered in queue order.
    later = [db.queue_command(t["id"], s["id"], typ, {"agent": "codex"}) for typ in ("uninstall_hook", "install_hook")]
    delivered = db.pending_commands(s["id"])
    assert [(c["id"], c["type"]) for c in delivered] == [(hook, "install_hook"), (later[0], "uninstall_hook"), (later[1], "install_hook")]
    assert delivered[0]["params"] == {"agent": "codex"}
    assert db.get_command(t["id"], s["id"], hook)["status"] == "delivered"
    for extra in later:
        db.ack_command(s["id"], extra, {"status": "applied"})
    db.ack_command(s["id"], hook, {"status": "failed", "message": "unknown hook agent"})
    recent = db.list_commands(t["id"], s["id"], 10)
    assert [c["id"] for c in recent] == [later[1], later[0], hook, command]
    assert recent[2]["status"] == "failed" and recent[2]["message"] == "unknown hook agent"
    assert recent[2]["acked_at"] is not None and recent[3]["status"] == "applied"
    assert len(db.list_commands(t["id"], s["id"], 1)) == 1
    with pytest.raises(NotFound):
        db.get_command(other["id"], s["id"], hook)
    with pytest.raises(NotFound):
        db.list_commands(other["id"], s["id"])
    assert db.save_policy(t["id"], [{"id": "rule"}])["version"] == 2
    assert db.policy_version(t["id"]) == 2
    db.delete_sensor(t["id"], s["id"])
    with pytest.raises(NotFound):
        db.get_sensor_by_token(plain)


def test_device_identity_is_optional_and_heartbeats_only_fill_values(db):
    from openaidr.server.httpx import APIError

    t = tenant(db)
    blank = {"serial_number": "", "hardware_uuid": "", "machine_id": "", "source": ""}
    # Older sensors report no device identity and keep enrolling.
    legacy, _, _ = sensor(db, t["id"])
    assert db.get_sensor(t["id"], legacy["id"])["device"] == blank
    assert db.list_sensors(t["id"])[0][0]["device"] == blank
    token = db.create_enrollment_token(t["id"], "test", 3600, 1)
    reported = {"serial_number": " C02XYZ ", "hardware_uuid": "A1B2", "source": "ioreg"}
    s, _, _ = db.enroll_sensor({
        "enrollment_token": token["token"], "hostname": "host", "device": reported,
    })
    assert s["device"] == dict(blank, serial_number="C02XYZ", hardware_uuid="A1B2", source="ioreg")
    # A heartbeat without the object, and one with empty fields, keep stored values.
    db.record_heartbeat(s["id"], {})
    db.record_heartbeat(s["id"], {"device": {"serial_number": "", "machine_id": None}})
    assert db.get_sensor(t["id"], s["id"])["device"]["serial_number"] == "C02XYZ"
    db.record_heartbeat(s["id"], {"device": {"machine_id": "m-1", "ignored": "x"}})
    assert db.get_sensor(t["id"], s["id"])["device"] == {
        "serial_number": "C02XYZ", "hardware_uuid": "A1B2", "machine_id": "m-1", "source": "ioreg",
    }
    for invalid in ("text", {"serial_number": 7}, {"serial_number": "a" * 129}, {"source": "tab\there"}):
        with pytest.raises(APIError):
            db.record_heartbeat(s["id"], {"device": invalid})
        with pytest.raises(APIError):
            db.enroll_sensor({"enrollment_token": token["token"], "hostname": "h", "device": invalid})
    assert db.get_sensor(t["id"], s["id"])["device"]["machine_id"] == "m-1"
    assert db.scalar("SELECT count(*) FROM sensors WHERE tenant_id=$1", t["id"]) == 2
    # A reinstalled machine enrolls again with the same serial; both rows name
    # each other. Blank identifiers never match, and other tenants never see it.
    again_token = db.create_enrollment_token(t["id"], "test", 3600, 1)
    again, _, _ = db.enroll_sensor({
        "enrollment_token": again_token["token"], "hostname": "host-renamed",
        "device": {"serial_number": "C02XYZ", "source": "ioreg"},
    })
    other_tenant = tenant(db)
    foreign_token = db.create_enrollment_token(other_tenant["id"], "test", 3600, 1)
    db.enroll_sensor({
        "enrollment_token": foreign_token["token"], "hostname": "elsewhere",
        "device": {"serial_number": "C02XYZ"},
    })
    by_id = {str(row["id"]): row for row in db.list_all_sensors(t["id"])}
    assert [m["id"] for m in by_id[str(s["id"])]["same_hardware"]] == [again["id"]]
    match = by_id[str(again["id"])]["same_hardware"]
    assert [(m["id"], m["hostname"], m["status"]) for m in match] == [(s["id"], "host", "online")]
    assert by_id[str(legacy["id"])]["same_hardware"] == []
    assert db.get_sensor(t["id"], again["id"])["same_hardware"][0]["id"] == s["id"]
    assert db.get_sensor(other_tenant["id"], db.list_all_sensors(other_tenant["id"])[0]["id"])["same_hardware"] == []
    db.delete_sensor(t["id"], s["id"])
    assert db.get_sensor(t["id"], again["id"])["same_hardware"] == []


def test_evidence_search_matches_retained_identities_and_exclusive_day_bounds(db):
    t, other = tenant(db), tenant(db)
    device, _, _ = sensor(db, t["id"])
    other_device, _, _ = sensor(db, other["id"])
    start = now().replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    base = {"agent": {"product": "codex"}, "host": {"user": "Alice_%", "hostname": "Dev_%"},
            "session": {"id": "Session_%A"}, "kind": "command", "command": {"text": "echo hello"}}
    events = [{**base, "id": new_id(), "time": stamp.isoformat()} for stamp in
              (start, end - timedelta(microseconds=1), end)]
    events += [{**base, "id": new_id(), "time": start.isoformat(), "host": {"user": "Bob", "hostname": "Laptop"}},
               {"id": new_id(), "time": start.isoformat(), "kind": "sensor"}]
    db.ingest_batch(device, events)
    other_event = {**base, "id": new_id(), "time": start.isoformat()}
    db.ingest_batch(other_device, [other_event])
    filters = {"username": "ALICE_%", "hostname": "dev_%", "session": "_%A", "kind": "command",
               "since": start, "before": end}
    rows, cursor = db.list_events(t["id"], filters, {"limit": 1})
    assert [row["id"] for row in rows] == [events[1]["id"]] and cursor
    rows, cursor = db.list_events(t["id"], filters, {"limit": 1, "cursor": cursor})
    assert [row["id"] for row in rows] == [events[0]["id"]] and not cursor
    assert [r["id"] for r in db.list_events(other["id"], filters)[0]] == [other_event["id"]]
    assert db.list_events(t["id"], {**filters, "session": "session_%a"})[0] == []
    assert db.list_events(t["id"], {**filters, "hostname": "missing"})[0] == []
    assert db.list_events(t["id"], {**filters, "kind": "prompt"})[0] == []
    stored = db.get_event(t["id"], events[0]["id"])
    assert len(db.list_events(t["id"], {"session": str(stored["session_id"])})[0]) == 3
    assert len(db.list_events(t["id"], {"username": "_%"})[0]) == 3
    assert len(db.list_events(t["id"], {"hostname": "Laptop"})[0]) == 1


def test_ingest_inventory_findings_pagination_and_overviews(db):
    t = tenant(db)
    other = tenant(db)
    s, _, _ = sensor(db, t["id"])
    base = {
        "time": now().isoformat(),
        "agent": {"product": "JeVAgent", "model": "test-model"},
        "host": {"user": "alice"},
        "session": {"id": "session-a", "cwd": "/tmp"},
    }
    events = [
        {**base, "id": new_id(), "kind": "command", "command": {"text": "echo hello"}},
        {**base, "id": new_id(), "kind": "session.end"},
    ]
    assert db.ingest_batch(s, events) == {"accepted": 2, "duplicates": 0}
    assert db.ingest_batch(s, events) == {"accepted": 0, "duplicates": 2}
    rows, cursor = db.list_events(t["id"], page={"limit": 1})
    assert len(rows) == 1 and cursor
    assert len(db.list_events(t["id"], page={"limit": 1, "cursor": cursor})[0]) == 1
    assert db.list_events(other["id"])[0] == []
    agents, _ = db.list_agents(t["id"])
    assert (
        len(agents) == 1
        and agents[0]["events_total"] == 2
        and agents[0]["sessions_total"] == 1
    )
    sessions, _ = db.list_agent_sessions(t["id"], agents[0]["id"])
    assert (
        sessions[0]["commands"] == 1
        and sessions[0]["tool_calls"] == 1
        and sessions[0]["ended_at"]
    )
    assert db.list_agents(t["id"], {"q": "alice"})[0]
    for query in ("JEV", "gUaRd", "GuardrailAgent"):
        matches, _ = db.list_agents(t["id"], {"q": query})
        assert [agent["id"] for agent in matches] == [agents[0]["id"]]
        assert db.list_agents(other["id"], {"q": query})[0] == []
    assert db.list_events(t["id"], {"q": "hello"})[0]
    stored = db.get_event(t["id"], events[0]["id"])
    f = {
        "tenant_id": t["id"],
        "rule_id": "test-rule",
        "category": "destructive_command",
        "severity": "high",
        "title": "test finding",
        "agent_id": stored["agent_id"],
        "session_id": stored["session_id"],
        "sensor_id": s["id"],
        "host": {"hostname": "host"},
        "event_ids": [stored["id"]],
        "primary_event_id": stored["id"],
        "first_event_at": stored["time"],
    }
    assert db.insert_finding(f) and not db.insert_finding(f)
    findings, _ = db.list_findings(t["id"])
    user = db.create_user(
        t["id"], new_id() + "@test.invalid", "Analyst", "hash", "analyst"
    )
    fid = findings[0]["id"]
    assert (
        db.update_finding(
            t["id"], fid, {"assignee_id": user["id"], "status": "triaged"}
        )["assignee"]["name"]
        == "Analyst"
    )
    assert (
        db.add_note(t["id"], fid, user["id"], "Review")["author"]["name"] == "Analyst"
    )
    assert (
        db.create_action(t["id"], fid, "note", {}, "applied", user["id"], True)[
            "status"
        ]
        == "applied"
    )
    assert db.list_actions(t["id"])[0] and db.actions_for_finding(t["id"], fid)
    assert db.get_overview(t["id"])["events"] == 2
    assert db.detect_lag(t["id"]) == 2
    last = db.events_after(t["id"], Cursor())[-1]
    db.set_detect_cursor(t["id"], Cursor(last["received_at"], last["id"]))
    assert db.detect_lag(t["id"]) == 0
    db.audit(t["id"], {"type": "user", "id": user["id"], "name": "Analyst"}, "test")
    assert db.list_audit(t["id"])[0][0]["actor"]["name"] == "Analyst"


def captured_event(sequence, kind="prompt", **evidence):
    return {
        "id": new_id(),
        "time": (now() + timedelta(seconds=sequence)).isoformat(),
        "agent": {"product": "claude-code"},
        "host": {"user": "alice"},
        "session": {"id": "captured-session"},
        "kind": kind,
        "evidence": {
            "version": 1,
            "logical_id": f"logical-{sequence}",
            "observation_id": f"observation-{sequence}",
            "stream_id": "stream-a",
            "sequence": sequence,
            "part": 1,
            "gaps": [],
            **evidence,
        },
    }


def test_session_evidence_preserves_order_observations_and_scope(db):
    t, other = tenant(db), tenant(db)
    s, _, _ = sensor(db, t["id"])
    call = captured_event(10, "tool.call", logical_id="tool-1")
    call["tool"] = {"name": "Bash", "call_id": "native-1", "input": {"command": "echo hello"}}
    command = captured_event(10, "command", logical_id="tool-1", observation_id="derived-1", part=2)
    command["tool"] = call["tool"]
    command["command"] = {"text": "echo hello"}
    result = captured_event(11, "tool.result")
    result["tool"] = {"name": "Bash", "call_id": "native-1", "output": "hello"}
    # Source sequence wins over conflicting wall-clock timestamps.
    result["time"] = (now() - timedelta(hours=1)).isoformat()
    gap = captured_event(0, "sensor", part=0, gaps=["skipped_history"])
    end = captured_event(12, "session.end")
    legacy = captured_event(1)
    del legacy["evidence"]
    second_stream = captured_event(1, stream_id="stream-b", observation_id="other-stream")
    events = [end, result, command, call, legacy, second_stream, gap]
    assert db.ingest_batch(s, events) == {"accepted": 7, "duplicates": 0}
    assert db.ingest_batch(s, events) == {"accepted": 0, "duplicates": 7}
    session_id = db.get_event(t["id"], call["id"])["session_id"]
    assert db.get_event(t["id"], gap["id"])["session_id"] == session_id
    assert db.get_session_row(t["id"], session_id)["ended_at"]

    pages, observations, cursor = [], [], ""
    while True:
        page = db.list_session_evidence(t["id"], session_id, limit=2, cursor=cursor)
        pages.append(page)
        observations.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert [row["id"] for row in observations] == [
        event["id"] for event in (legacy, gap, call, command, result, end, second_stream)
    ]
    assert [row["body"] for row in observations] == [
        legacy, gap, call, command, result, end, second_stream
    ]
    assert observations[2]["evidence"]["logical_id"] == observations[3]["evidence"]["logical_id"]
    assert observations[2]["evidence"]["observation_id"] != observations[3]["evidence"]["observation_id"]
    assert observations[2]["evidence"]["tool_call_id"] == observations[4]["evidence"]["tool_call_id"]
    assert pages[0]["coverage"]["status"] == "incomplete"
    assert pages[0]["coverage"]["gaps"] == ["skipped_history"]
    assert pages[0]["coverage"]["legacy_observations"] == 1
    for page in pages:
        assert page["coverage"]["scope"] == "page"
        assert page["coverage"]["delivery"] == "unknown"
        assert page["coverage"]["cross_stream_order"] == "unknown"
    assert pages[-1]["coverage"]["status"] == "unknown"
    with pytest.raises(NotFound):
        db.list_session_evidence(other["id"], session_id)

    another_sensor, _, _ = sensor(db, t["id"])
    other_call = {**call, "id": new_id()}
    db.ingest_batch(another_sensor, [other_call])
    other_session = db.get_event(t["id"], other_call["id"])["session_id"]
    assert other_session != session_id
    assert len(db.list_session_evidence(t["id"], other_session)["items"]) == 1
    assert len(db.list_session_evidence(t["id"], session_id)["items"]) == 7
    heartbeat = {**legacy, "id": new_id(), "kind": "sensor"}
    db.ingest_batch(s, [heartbeat])
    assert db.get_event(t["id"], heartbeat["id"])["session_id"] is None


def test_session_evidence_handles_unknown_stored_contracts_and_bad_cursors(db):
    from openaidr.core.event import EVIDENCE_GAPS, validate_evidence

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    # Reapply the migration over historical rows, including metadata that newer
    # receivers would reject, to exercise the generated-column backfill too.
    db.execute("ALTER TABLE events DROP COLUMN evidence_stream, DROP COLUMN evidence_sequence, DROP COLUMN evidence_part")
    db.execute("DROP FUNCTION session_evidence_valid_v1(jsonb)")
    db.execute("DELETE FROM schema_migrations WHERE version=28")
    legacy = captured_event(1, "session.end")
    del legacy["evidence"]
    events = [legacy]
    # Old database rows and future contracts must not trigger unsafe SQL casts.
    for sequence in ((1 << 100), "no-number", -1, 1.0, 1.5, True, None):
        event = captured_event(2)
        event["evidence"]["sequence"] = sequence
        events.append(event)
    for fields in (
        {"version": "1"}, {"version": 1.0}, {"version": True},
        {"logical_id": ""}, {"observation_id": "x" * 129},
        {"stream_id": "stream\n"}, {"stream_id": "s\u00e9quence"},
        {"part": 1 << 63}, {"part": -1}, {"part": True},
        {"gaps": [["skipped_content"]]}, {"gaps": [None]},
        {"gaps": ["future_gap"]}, {"gaps": ["parser_restart"] * 33},
        {"gaps": {}},
    ):
        events.append(captured_event(2, **fields))
    for metadata in ([], None, {"version": 2}, {"version": 1}):
        event = captured_event(2)
        event["evidence"] = metadata
        events.append(event)
    db.ingest_batch(s, events)
    assert db.migrate() == ["0028_session_evidence_order.sql"]
    session_id = db.get_event(t["id"], legacy["id"])["session_id"]
    result = db.list_session_evidence(t["id"], session_id)
    assert result["coverage"]["status"] == "unknown"
    assert result["coverage"]["legacy_observations"] == 1
    assert result["coverage"]["unknown_observations"] == len(events) - 1
    assert all(row["evidence"]["logical_id"] is None for row in result["items"])
    valid = [
        captured_event(0, part=0, stream_id="._:-Az09", gaps=sorted(EVIDENCE_GAPS)),
        captured_event(3, part=(1 << 63) - 1, gaps=["parser_restart"] * 32),
    ]
    valid[1]["evidence"]["sequence"] = (1 << 63) - 1
    db.ingest_batch(s, valid)
    stored = db.many(
        "SELECT body,session_evidence_valid_v1(body->'evidence') AS valid,"
        "evidence_stream,evidence_sequence,evidence_part FROM events WHERE tenant_id=$1",
        t["id"],
    )
    for row in stored:
        metadata = row["body"].get("evidence")
        assert row["valid"] is (not validate_evidence(metadata))
        assert (row["evidence_stream"], row["evidence_sequence"], row["evidence_part"]) == (
            (metadata["stream_id"], metadata["sequence"], metadata["part"])
            if row["valid"] else ("", -1, -1)
        )

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    position = ["stream-a", 2, 1, now().isoformat(), new_id()]
    for bad in ("???", "a" * 1025, encode({}), encode(position[:4]),
                encode(["a", True, 1, *position[3:]]),
                encode(["a", 1 << 64, 1, *position[3:]]),
                encode(["a", -1, 1, *position[3:]]),
                encode(["a", 1, -1, *position[3:]]),
                encode(["a\n", 1, 1, *position[3:]]),
                encode(["a b", 1, 1, *position[3:]]),
                encode(["", 1, 1, *position[3:]]),
                encode([*position[:3], "2026-01-01", position[4]])):
        with pytest.raises(ValueError, match="invalid cursor"):
            db.list_session_evidence(t["id"], session_id, cursor=bad)
    empty = db.list_session_evidence(
        t["id"], session_id, cursor=encode(["z", *position[1:]])
    )
    assert empty["items"] == []
    assert empty["coverage"]["status"] == "unknown"


def test_session_evidence_late_page_uses_index_range(db, monkeypatch):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    first = captured_event(0)
    db.ingest_batch(s, [first])
    session_id = db.get_event(t["id"], first["id"])["session_id"]
    # Bulk-load one long transcript without spending test time on inventory
    # updates. This remains real stored event data and the real page query.
    db.execute(
        """INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body)
           SELECT md5(e.id::text||':'||n::text)::uuid,e.tenant_id,e.sensor_id,
                  e.agent_id,e.session_id,e.time,e.kind,e.product,
                  e.body||jsonb_build_object(
                      'id',md5(e.id::text||':'||n::text),
                      'evidence',(e.body->'evidence')||jsonb_build_object(
                          'sequence',n,'logical_id','logical-'||n::text,
                          'observation_id','observation-'||n::text))
           FROM events e CROSS JOIN generate_series(1,6000) n WHERE e.id=$1""",
        first["id"],
    )
    db.execute("ANALYZE events")
    cursor = base64.urlsafe_b64encode(json.dumps([
        "stream-a", 5500, 1, first["time"], "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ]).encode()).decode().rstrip("=")
    queries, many = [], db.many

    def capture_query(query, *args, **kwargs):
        if "evidence_stream" in query:
            queries.append((query, args))
        return many(query, *args, **kwargs)

    monkeypatch.setattr(db, "many", capture_query)
    result = db.list_session_evidence(t["id"], session_id, limit=10, cursor=cursor)
    assert [row["evidence"]["sequence"] for row in result["items"]] == list(range(5501, 5511))
    assert result["next_cursor"]
    assert len(queries) == 1
    query, args = queries[0]
    plan = db.scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) " + query, *args)[0]["Plan"]
    nodes, pending = [], [plan]
    while pending:
        node = pending.pop()
        nodes.append(node)
        pending.extend(node.get("Plans", []))
    # The planner may sort the indexed tails from separate daily partitions.
    # It must still seek past the first 5,500 records, without a full scan.
    assert not any(node["Node Type"] == "Seq Scan"
                   and node.get("Actual Rows", 0) + node.get("Rows Removed by Filter", 0) > 0
                   for node in nodes), json.dumps(plan, indent=2)
    indexes = {row["name"] for row in db.many(
        "SELECT relid::regclass::text AS name FROM pg_partition_tree('events_session_evidence_order_idx') WHERE isleaf")}
    scans = [node for node in nodes if node.get("Index Name") in indexes and node["Actual Rows"]]
    assert len(scans) == 1, plan
    scan = scans[0]
    assert scan["Node Type"] == "Index Scan"
    assert all(key in scan["Index Cond"] for key in ("tenant_id", "session_id", "evidence_stream", "evidence_sequence", "5500"))
    assert "> ROW(" in scan["Index Cond"]
    assert 11 <= scan["Actual Rows"] <= 500
    assert scan.get("Rows Removed by Filter", 0) == 0
    assert scan.get("Shared Hit Blocks", 0) + scan.get("Shared Read Blocks", 0) < 100


def test_session_evidence_http_uses_tenant_auth_and_ingest_validation(db):
    from fastapi.testclient import TestClient
    from openaidr.server.app import create_app
    from openaidr.server.auth import CONSOLE_COOKIE
    from openaidr.server.config import Config

    t, other = tenant(db), tenant(db)
    s, sensor_token, _ = sensor(db, t["id"])
    cfg = Config()
    cfg.set_services("api,ingest")
    client = TestClient(create_app(cfg, db), headers={"X-OpenAIDR-CSRF": "1"})
    headers = {"Authorization": "Bearer " + sensor_token}
    event = captured_event(1, "tool.call")
    payload = {"body": "message", "received_at": "customer timestamp", "username": "alice",
               "tenant_id": "customer tenant", "token_hash": "captured value"}
    event["tool"] = {"name": "webhook", "input": {"nested": [payload]}, "output": payload}
    malformed = copy.deepcopy(event)
    malformed["id"] = new_id()
    malformed["evidence"]["sequence"] = True
    legacy = captured_event(2, "session.end")
    del legacy["evidence"]
    ingested = client.post("/ingest/v1/events", headers=headers,
                           json={"events": [malformed, event, legacy]})
    assert ingested.status_code == 200, ingested.text
    assert ingested.json()["accepted"] == 2
    assert ingested.json()["rejected"][0]["id"] == malformed["id"]
    assert "evidence.sequence" in ingested.json()["rejected"][0]["reason"]
    session_id = db.get_event(t["id"], event["id"])["session_id"]
    path = f"/api/v1/sessions/{session_id}/evidence"
    assert client.get(path).status_code == 401
    user = db.create_user(t["id"], new_id() + "@test.invalid", "Analyst", "hash", "analyst")
    client.cookies.set(CONSOLE_COOKIE, db.create_session(user["id"], t["id"]))
    for event_path in (
        "/api/v1/events", f"/api/v1/events/{event['id']}", "/api/v1/events/live",
        f"/api/v1/sessions/{session_id}/events", path,
    ):
        reply = client.get(event_path)
        assert reply.status_code == 200, (event_path, reply.text)
        data = reply.json()
        items = data.get("items", [data])
        captured = next(item for item in items if item["id"] == event["id"])
        assert captured["tool"] == event["tool"]
    assert db.get_event(t["id"], event["id"])["body"]["tool"] == event["tool"]
    result = client.get(path, params={"limit": 1})
    assert result.status_code == 200, result.text
    assert len(result.json()["items"]) == 1
    cursor = result.json()["next_cursor"]
    assert cursor
    next_page = client.get(path, params={"cursor": cursor})
    assert next_page.status_code == 200, next_page.text
    assert next_page.json()["items"][0]["id"] == event["id"]
    assert next_page.json()["coverage"]["status"] == "unknown"
    assert client.get(path, params={"cursor": "invalid"}).status_code == 400
    assert client.get(path, params={"limit": -1}).status_code == 400
    # The established operator endpoint remains available to the same tenant.
    assert len(client.get(f"/api/v1/sessions/{session_id}/events").json()["items"]) == 2
    other_user = db.create_user(other["id"], new_id() + "@test.invalid", "Other", "hash", "owner")
    client.cookies.set(CONSOLE_COOKIE, db.create_session(other_user["id"], other["id"]))
    assert client.get(path, params={"cursor": cursor}).status_code == 404
    assert client.get(f"/api/v1/events/{event['id']}").status_code == 404
    assert client.get("/api/v1/events").json()["items"] == []


def test_session_gap_metadata_preserves_native_lifecycle(db, tmp_path):
    from openaidr.sensor.collectors import Collector, Offsets

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    instant = now() - timedelta(hours=1)
    records = [
        {"type": "session_meta", "payload": {"id": "closed-codex-session"}},
        {"type": "response_item", "payload": {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": "hello"}]}},
        {"type": "event_msg", "payload": {"type": "task_complete"}},
    ]
    for index, record in enumerate(records):
        record["timestamp"] = (instant + timedelta(seconds=index)).isoformat()
    path = tmp_path / "session.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    offsets = tmp_path / "offsets.json"
    events = []

    def emit(event):
        events.append({**event, "id": new_id()})

    Collector("codex-cli", [], [str(path)], Offsets(offsets),
              backfill=True, emit=emit).poll(initial=True)
    assert [event["kind"] for event in events] == ["session.start", "prompt", "session.end"]
    db.ingest_batch(s, events)
    stored = db.get_event(t["id"], events[0]["id"])
    session_id, agent_id = stored["session_id"], stored["agent_id"]
    closed = db.get_session_row(t["id"], session_id)
    agent = db.get_agent(t["id"], agent_id)
    assert closed["ended_at"]

    events.clear()
    restarted = Collector("codex-cli", [], [str(path)], Offsets(offsets), emit=emit)
    restarted.poll(initial=True)
    assert len(events) == 1 and events[0]["kind"] == "sensor"
    assert "parser_restart" in events[0]["evidence"]["gaps"]
    db.ingest_batch(s, events)
    gap = db.get_event(t["id"], events[0]["id"])
    assert gap["session_id"] == session_id
    after_gap = db.get_session_row(t["id"], session_id)
    assert after_gap["events_total"] == closed["events_total"] + 1
    for key in ("started_at", "last_event_at", "ended_at"):
        assert after_gap[key] == closed[key]
    after_agent = db.get_agent(t["id"], agent_id)
    assert after_agent["events_total"] == agent["events_total"] + 1
    for key in ("first_seen", "last_seen"):
        assert after_agent[key] == agent[key]

    events.clear()
    resumed = copy.deepcopy(records[1])
    resumed["timestamp"] = (instant + timedelta(minutes=1)).isoformat()
    with path.open("a") as stream:
        stream.write(json.dumps(resumed) + "\n")
    restarted.poll()
    db.ingest_batch(s, events)
    after_native = db.get_session_row(t["id"], session_id)
    assert after_native["started_at"] == closed["started_at"]
    assert after_native["last_event_at"] == instant + timedelta(minutes=1)
    assert after_native["ended_at"] is None


@pytest.mark.parametrize("hours", [-1, 1])
def test_session_gap_placeholder_uses_first_native_chronology(db, hours):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    import time

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    gap = captured_event(0, "sensor", gaps=["skipped_history"])
    db.ingest_batch(s, [gap])
    stored = db.get_event(t["id"], gap["id"])
    session_id, agent_id = stored["session_id"], stored["agent_id"]
    instant = now() + timedelta(hours=hours)
    prompt, end = captured_event(1), captured_event(2, "session.end")
    prompt["time"] = instant.isoformat()
    end["time"] = (instant + timedelta(seconds=1)).isoformat()
    with db.transaction() as conn:
        with conn.transaction(force_rollback=True):
            db.ingest_batch(s, [prompt], conn)
            assert db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", agent_id, conn=conn)
            assert db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", session_id, conn=conn)
    assert not db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", agent_id)
    assert not db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", session_id)
    entered, waiting = Event(), {}

    def ingest_end():
        with db.transaction() as conn:
            conn.execute("SET LOCAL statement_timeout='5s'")
            waiting["pid"] = db.scalar("SELECT pg_backend_pid()", conn=conn)
            entered.set()
            return db.ingest_batch(s, [end], conn)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with db.transaction() as conn:
            db.ingest_batch(s, [prompt], conn)
            writer = db.scalar("SELECT pg_backend_pid()", conn=conn)
            future = executor.submit(ingest_end)
            assert entered.wait(3)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if db.scalar("SELECT $1=ANY(pg_blocking_pids($2))", writer, waiting["pid"]):
                    break
            else:
                pytest.fail("concurrent ingestion did not wait for the agent row lock")
        assert future.result(timeout=5)["accepted"] == 1
    session = db.get_session_row(t["id"], session_id)
    agent = db.get_agent(t["id"], agent_id)
    assert session["started_at"] == agent["first_seen"] == instant
    assert session["last_event_at"] == agent["last_seen"] == instant + timedelta(seconds=1)
    assert session["ended_at"] == instant + timedelta(seconds=1)
    assert session["events_total"] == agent["events_total"] == 3


def test_ingestion_preserves_chronology_without_reading_event_history(db, monkeypatch):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    instant = now() - timedelta(hours=1)
    batch = []
    for product in ("claude-code", "codex-cli"):
        gap = captured_event(0, "sensor", gaps=["skipped_history"])
        gap["agent"]["product"] = product
        batch.append(gap)
        for sequence in (20, 10, 30):
            event = captured_event(sequence)
            event["agent"]["product"] = product
            event["time"] = (instant + timedelta(seconds=sequence)).isoformat()
            batch.append(event)

    execute, history_reads = db._execute, []

    def measured(conn, query, args, mode):
        if "FROM events" in query:
            history_reads.append(query)
        return execute(conn, query, args, mode)

    monkeypatch.setattr(db, "_execute", measured)
    assert db.ingest_batch(s, batch) == {"accepted": 8, "duplicates": 0}
    assert history_reads == []
    assert db.ingest_batch(s, batch) == {"accepted": 0, "duplicates": 8}
    assert history_reads == []
    later = captured_event(40)
    later["time"] = (instant + timedelta(seconds=40)).isoformat()
    assert db.ingest_batch(s, [later]) == {"accepted": 1, "duplicates": 0}
    assert history_reads == []
    for event in (batch[1], batch[5]):
        stored = db.get_event(t["id"], event["id"])
        agent = db.get_agent(t["id"], stored["agent_id"])
        session = db.get_session_row(t["id"], stored["session_id"])
        assert agent["first_seen"] == session["started_at"] == instant + timedelta(seconds=10)
        is_claude = event["agent"]["product"] == "claude-code"
        assert agent["last_seen"] == session["last_event_at"] == instant + timedelta(seconds=40 if is_claude else 30)
        assert agent["events_total"] == session["events_total"] == (5 if is_claude else 4)


def test_native_activity_survives_history_removal_and_store_restart(db):
    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    instant = now() - timedelta(days=2)
    first, end = captured_event(1), captured_event(2, "session.end")
    first["time"] = instant.isoformat()
    end["time"] = (instant + timedelta(seconds=1)).isoformat()
    db.ingest_batch(s, [first, end])
    stored = db.get_event(t["id"], first["id"])
    agent_id, session_id = stored["agent_id"], stored["session_id"]
    db.execute("DELETE FROM events WHERE tenant_id=$1", t["id"])

    reopened = Store(db.url)
    try:
        gap = captured_event(3, "sensor", gaps=["parser_restart"])
        reopened.ingest_batch(s, [gap])
        session = reopened.get_session_row(t["id"], session_id)
        assert session["started_at"] == instant
        assert session["last_event_at"] == session["ended_at"] == instant + timedelta(seconds=1)
        assert reopened.get_event(t["id"], gap["id"])["body"]["evidence"]["gaps"] == ["parser_restart"]
        later = captured_event(4)
        later["time"] = (instant + timedelta(hours=1)).isoformat()
        reopened.ingest_batch(s, [later])
        session = reopened.get_session_row(t["id"], session_id)
        agent = reopened.get_agent(t["id"], agent_id)
        assert session["started_at"] == agent["first_seen"] == instant
        assert session["last_event_at"] == agent["last_seen"] == instant + timedelta(hours=1)
        assert session["ended_at"] is None
        assert agent["events_total"] == session["events_total"] == 4
        assert reopened.ingest_batch(s, [later]) == {"accepted": 0, "duplicates": 1}

        # A new gap-only session must reset its own provisional dates without
        # resetting the existing agent's activity from its other session.
        gap = captured_event(5, "sensor", gaps=["skipped_history"])
        gap["session"]["id"] = "second-session"
        native = copy.deepcopy(gap)
        native.update(id=new_id(), kind="prompt", time=(instant + timedelta(hours=2)).isoformat())
        reopened.ingest_batch(s, [gap, native])
        stored = reopened.get_event(t["id"], native["id"])
        session = reopened.get_session_row(t["id"], stored["session_id"])
        agent = reopened.get_agent(t["id"], agent_id)
        assert session["started_at"] == session["last_event_at"] == instant + timedelta(hours=2)
        assert agent["first_seen"] == instant
        assert agent["last_seen"] == instant + timedelta(hours=2)
    finally:
        reopened.close()


def test_native_activity_migrations_preserve_records_and_concurrent_writers(db, tmp_path, monkeypatch):
    from pathlib import Path
    from openaidr.server import store

    gap_rows, native_rows = [], []
    for _ in range(2):
        t = tenant(db)
        s, _, _ = sensor(db, t["id"])
        gap = captured_event(0, "sensor", gaps=["skipped_history"])
        db.ingest_batch(s, [gap])
        gap_rows.append(db.get_event(t["id"], gap["id"]))
        native = captured_event(1)
        native["host"]["user"] = "native-user"
        db.ingest_batch(s, [native])
        native_rows.append(db.get_event(t["id"], native["id"]))

    db.execute("DROP TRIGGER events_native_activity ON events")
    db.execute("DROP FUNCTION record_native_activity()")
    db.execute("ALTER TABLE agents DROP COLUMN has_native_activity")
    db.execute("ALTER TABLE agent_sessions DROP COLUMN has_native_activity")
    db.execute("DELETE FROM schema_migrations WHERE version IN (66,67)")
    before = {table: db.many(f"SELECT to_jsonb(t) AS row FROM {table} t ORDER BY id")
              for table in ("agents", "agent_sessions", "events")}

    # Apply only DDL first, as a rolling deployment or a resumed migration can.
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    source = Path(store.__file__).with_name("migrations") / "0066_native_activity_state.sql"
    (migrations / source.name).write_text(source.read_text())
    with monkeypatch.context() as patch:
        patch.setattr(store, "__file__", str(tmp_path / "store.py"))
        assert db.migrate() == [source.name]

    # An older writer does not know about the flags. Its insert must still
    # maintain them, even if the event disappears before the backfill sees it.
    legacy_id = new_id()
    gap = gap_rows[0]
    db.execute("""INSERT INTO events(id,tenant_id,sensor_id,agent_id,session_id,time,kind,product,body)
        SELECT $1,tenant_id,sensor_id,agent_id,session_id,time,'prompt',product,body
        FROM events WHERE id=$2""", legacy_id, gap["id"])
    db.execute("DELETE FROM events WHERE id=$1", legacy_id)
    assert db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", gap["agent_id"])
    assert db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", gap["session_id"])
    assert db.migrate() == ["0067_native_activity_backfill.sql"]
    assert db.migrate() == []
    for row in [*native_rows, gap_rows[0]]:
        assert db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", row["agent_id"])
        assert db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", row["session_id"])
    assert not db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", gap_rows[1]["agent_id"])
    assert not db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", gap_rows[1]["session_id"])
    for table, rows in before.items():
        after = db.many(f"SELECT to_jsonb(t)-'has_native_activity' AS row FROM {table} t ORDER BY id")
        assert after == rows


def test_native_activity_backfill_waits_for_complete_ingest_batch(db):
    from concurrent.futures import ThreadPoolExecutor
    import time

    t = tenant(db)
    s, _, _ = sensor(db, t["id"])
    native, gaps = [], []
    for product in ("claude-code", "codex-cli"):
        event = captured_event(0)
        event["agent"]["product"] = product
        native.append(event)
        gap = captured_event(1, "sensor", gaps=["parser_restart"])
        gap["agent"]["product"] = product
        gaps.append(gap)
    db.ingest_batch(s, native)
    stored = [db.get_event(t["id"], event["id"]) for event in native]
    before = [(db.get_agent(t["id"], row["agent_id"]),
               db.get_session_row(t["id"], row["session_id"])) for row in stored]
    # Model the partially initialized state between migrations 0066 and 0067.
    # A is already marked, so the backfill can lock B before reaching session A.
    db.execute("UPDATE agents SET has_native_activity=(id=$1)", stored[0]["agent_id"])
    db.execute("UPDATE agent_sessions SET has_native_activity=false")
    db.execute("DELETE FROM schema_migrations WHERE version=67")

    with ThreadPoolExecutor(max_workers=1) as executor:
        with db.transaction() as writer:
            writer.execute("SET LOCAL statement_timeout='5s'")
            writer_pid = db.scalar("SELECT pg_backend_pid()", conn=writer)
            assert db.ingest_batch(s, gaps[:1], writer)["accepted"] == 1
            pending = executor.submit(db.migrate)
            deadline = time.monotonic() + 5
            while not db.scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                "AND objid=684021559 AND granted AND $1=ANY(pg_blocking_pids(pid)))",
                writer_pid,
            ):
                assert time.monotonic() < deadline, "Backfill did not wait for the live batch"
                time.sleep(0.01)
            # The batch must reach its second agent and commit while the
            # backfill waits, rather than waiting for a row the backfill owns.
            assert db.ingest_batch(s, gaps[1:], writer)["accepted"] == 1
        assert pending.result(timeout=5) == ["0067_native_activity_backfill.sql"]
    assert db.migrate() == []
    for row, (agent, session), gap in zip(stored, before, gaps):
        assert db.scalar("SELECT has_native_activity FROM agents WHERE id=$1", row["agent_id"])
        assert db.scalar("SELECT has_native_activity FROM agent_sessions WHERE id=$1", row["session_id"])
        assert db.get_agent(t["id"], row["agent_id"]) == {**agent, "events_total": 2}
        assert db.get_session_row(t["id"], row["session_id"]) == {**session, "events_total": 2}
        assert db.get_event(t["id"], gap["id"])["body"] == gap
    assert db.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", t["id"]) == 4


def test_live_events_follow_arrival_order_and_continue_from_a_cursor(db):
    t = tenant(db)
    other = tenant(db)
    s, _, _ = sensor(db, t["id"])
    base = {
        "agent": {"product": "codex-cli"},
        "host": {"user": "alice"},
        "session": {"id": "session-live", "cwd": "/tmp"},
    }
    early = (now() - timedelta(hours=1)).isoformat()
    first = [
        {**base, "id": new_id(), "time": now().isoformat(), "kind": "prompt", "text": "one"},
        {**base, "id": new_id(), "time": now().isoformat(), "kind": "command", "command": {"text": "ls"}},
    ]
    assert db.ingest_batch(s, first)["accepted"] == 2
    rows, cursor, more = db.live_events(t["id"], limit=1)
    # Newest arrival first, and the cursor marks it even when the page is cut.
    assert [r["kind"] for r in rows] == ["command"] and cursor and not more
    rows, cursor, more = db.live_events(t["id"])
    assert [r["body"]["kind"] for r in rows] == ["command", "prompt"]
    assert decode_live_cursor(cursor).position.id == rows[0]["id"]
    # Nothing new: the cursor is handed back unchanged.
    assert db.live_events(t["id"], cursor) == ([], cursor, False)
    # A late event with an old agent timestamp still arrives after the cursor.
    later = [
        {**base, "id": new_id(), "time": early, "kind": "tool.result", "tool": {"name": "shell", "output": "ok"}},
        {**base, "id": new_id(), "time": now().isoformat(), "kind": "session.end"},
    ]
    assert db.ingest_batch(s, later)["accepted"] == 2
    rows, next_cursor, more = db.live_events(t["id"], cursor, limit=1)
    assert [r["kind"] for r in rows] == ["tool.result"] and more
    rows, final, more = db.live_events(t["id"], next_cursor, limit=1)
    assert [r["kind"] for r in rows] == ["session.end"] and not more
    assert db.live_events(t["id"], final) == ([], final, False)
    assert [r["kind"] for r in db.live_events(t["id"], cursor, {"kind": "session.end"})[0]] == ["session.end"]
    assert db.live_events(t["id"], f={"product": "claude-code"})[0] == []
    assert db.live_events(t["id"], f={"source": "otlp"})[0] == []
    assert len(db.live_events(t["id"], f={"source": "collector"})[0]) == 4
    assert db.live_events(other["id"])[0] == []
    with pytest.raises(ValueError):
        db.live_events(t["id"], f={"source": "bogus"})


def test_live_events_deliver_rows_committed_in_reverse_stamp_order(db):
    t = tenant(db)
    one, _, _ = sensor(db, t["id"])
    two, _, _ = sensor(db, t["id"])

    def event(text):
        return {
            "agent": {"product": "codex-cli"},
            "session": {"id": "s-" + text},
            "id": new_id(),
            "time": now().isoformat(),
            "kind": "prompt",
            "text": text,
        }

    db.ingest_batch(one, [event("seed")])
    _, cursor, _ = db.live_events(t["id"])
    # Sensor one's batch inserts first (earlier stamp) but commits after
    # sensor two's; the live poll in between sees only the later one.
    early, later = event("early"), event("later")
    with db.transaction() as a:
        db.ingest_batch(one, [early], a)
        db.ingest_batch(two, [later])
        rows, cursor, more = db.live_events(t["id"], cursor)
        assert [r["id"] for r in rows] == [later["id"]] and not more
    # A has committed now; the next poll returns it.
    rows, cursor, _ = db.live_events(t["id"], cursor)
    assert early["id"] in [r["id"] for r in rows]
    # With nothing pending, later polls repeat nothing.
    rows, again, more = db.live_events(t["id"], cursor)
    assert rows == [] and again == cursor and more is False
    # A plain event cursor is still accepted as a live cursor.
    plain = decode_live_cursor(cursor).position.encode()
    assert db.live_events(t["id"], plain)[0] == []
    with pytest.raises(ValueError):
        decode_live_cursor(cursor.split(".")[0] + ".bm90LWEtdGltZQ")


def test_a_delayed_savepoint_row_arrives_after_more_than_a_page_of_later_rows(db):
    t = tenant(db)
    one, _, _ = sensor(db, t["id"])
    two, _, _ = sensor(db, t["id"])

    def event(text, session):
        return {
            "agent": {"product": "codex-cli"},
            "session": {"id": session},
            "id": new_id(),
            "time": now().isoformat(),
            "kind": "prompt",
            "text": text,
        }

    db.ingest_batch(one, [event("seed", "seed")])
    _, cursor, _ = db.live_events(t["id"])
    delayed = event("delayed", "slow")
    seen = []
    with db.transaction() as a:
        # Written under a savepoint, as native telemetry translation does
        # (the outer transaction has already run a statement).
        a.execute("SELECT 1")
        with a.transaction():
            db.ingest_batch(one, [delayed], a)
        assert a.execute("SELECT pg_current_xact_id() IS NOT NULL").fetchone()
        # 600 later-stamped rows commit while the delayed row is pending.
        for batch in range(3):
            db.ingest_batch(two, [event(f"later-{batch}-{i}", "busy") for i in range(200)])
        more = True
        while more:
            rows, cursor, more = db.live_events(t["id"], cursor, limit=250)
            seen += [r["id"] for r in rows]
        assert len(seen) == 600 and delayed["id"] not in seen
    rows, cursor, _ = db.live_events(t["id"], cursor, limit=250)
    assert [r["id"] for r in rows] == [delayed["id"]]
    # Each row is returned once.
    assert db.live_events(t["id"], cursor)[0] == []


def test_credential_read_rule_is_split_without_brace_globs(db):
    from pathlib import Path
    from openaidr.core.policy import Policy
    from openaidr.server.app import default_policy_rules
    from openaidr.server.store import CREDENTIAL_GLOBS

    ssh = {"kind": "file.read", "file": {"path": "/home/a/.ssh/id_rsa"}}
    nested = {"kind": "file.read", "file": {"path": "/home/a/.aws/sso/cache/token.json"}}
    gcloud = {"kind": "file.read", "file": {"path": "/home/a/.gcloud/config"}}
    # A tenant's own stricter rule for the same files, added after the
    # built-in rules; the old brace rule never matched, so it always applied.
    block = {"id": "block", "name": "Block ssh reads", "action": "deny", "enabled": True,
             "match": {"path_glob": "**/.ssh/**"}}

    def action(rules, event):
        return Policy(policy={"rules": rules}).evaluate(event).get("action")

    # Policy globs have no brace groups, so the rule is one per directory,
    # nested files included, and it comes last.
    defaults = default_policy_rules()
    assert action(defaults, ssh) == "warn" and action(defaults, nested) == "warn"
    assert "rule" not in Policy(policy={"rules": defaults}).evaluate(gcloud)
    t = tenant(db)
    db.save_policy(t["id"], [*defaults, block])
    assert action(db.get_policy(t["id"])["rules"], ssh) == "deny"

    migration = Path(__file__).parents[1] / "src/openaidr/server/migrations/0037_split_credential_read_rule.sql"

    def store_legacy(policy):
        return any(r["match"].get("path_glob") == old["match"]["path_glob"] for r in policy["rules"])

    def stored_before(tenant_id, rules, asks=()):
        # As an earlier server stored it: save_policy now splits the rule.
        db.save_policy(tenant_id, [])
        db.execute(
            "UPDATE policies SET rules=$2::jsonb, ask_rule_ids=$3 WHERE tenant_id=$1",
            tenant_id, json.dumps(rules), list(asks),
        )
        return db.scalar("SELECT version FROM policies WHERE tenant_id=$1", tenant_id)

    old = {"id": "cred", "name": "Warn on credential file reads", "action": "warn",
           "enabled": True, "reason": "Credential stores.", "source": "builtin",
           "match": {"kinds": ["file.read"], "path_glob": "**/.{aws,ssh,kube}/*"}}
    # A custom rule with the same glob is not the built-in rule and is kept.
    custom = {"id": "custom", "name": "Allow odd dir", "action": "allow", "enabled": True,
              "match": {"path_glob": "**/.{aws,ssh,kube}/*"}}

    # Migration 0037 splits the built-in copy, keeps it last, and bumps the version.
    t = tenant(db)
    version = stored_before(t["id"], [old, custom, block])
    # Read before any migration, as written by an older server during a
    # rolling deploy: it is split in storage and gets a new version, so a
    # sensor already holding this version fetches the split rules.
    assert db.policy_version(t["id"]) == version + 1
    served = db.get_policy(t["id"])
    db.execute(migration.read_text())
    policy = db.get_policy(t["id"])
    # The migration stores what was already served, with the same ids.
    assert policy["rules"] == served["rules"]
    assert policy["version"] == version + 1
    rest, split = policy["rules"][:2], policy["rules"][2:]
    assert rest == [custom, block]
    assert [r["match"]["path_glob"] for r in split] == ["**/.aws/**", "**/.ssh/**", "**/.kube/**"]
    assert [r["name"] for r in split] == [f"Warn on credential file reads (.{d})" for d in ("aws", "ssh", "kube")]
    assert [r["id"] for r in split] == ["cred-aws", "cred-ssh", "cred-kube"]
    for r in split:
        assert {k: v for k, v in r.items() if k not in ("id", "name", "match")} == {
            k: v for k, v in old.items() if k not in ("id", "name", "match")
        }
    assert action(policy["rules"], ssh) == "deny"
    assert action(policy["rules"], nested) == "warn"
    # Already split: running it again changes nothing.
    db.execute(migration.read_text())
    assert db.get_policy(t["id"]) == policy

    # A copy changed to ask (stored as deny, id in ask_rule_ids) stays ask...
    asked = tenant(db)
    stored_before(asked["id"], [dict(old, action="deny")], asks=[old["id"]])
    db.execute(migration.read_text())
    assert [r["action"] for r in db.get_policy(asked["id"])["rules"]] == ["ask"] * 3
    # ...unless its id is shared, which already served it as a deny.
    shared = tenant(db)
    twin = dict(block, id=old["id"])
    stored_before(shared["id"], [dict(old, action="deny"), twin], asks=[old["id"]])
    db.execute(migration.read_text())
    assert [r["action"] for r in db.get_policy(shared["id"])["rules"]] == ["deny"] * 4
    # A split id another rule already has is replaced, so ids stay unique.
    clash = tenant(db)
    taken = dict(block, id="cred-aws")
    stored_before(clash["id"], [old, taken])
    db.execute(migration.read_text())
    rules = db.get_policy(clash["id"])["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)) == 4 and ids[0] == "cred-aws" and ids[2:] == ["cred-ssh", "cred-kube"]
    assert rules[0] == taken and action(rules, nested) == "warn"
    # The split and the reread hold the row, so an older instance cannot
    # write the legacy rule back between them and have it served.
    racing = tenant(db)
    split = db._split_stored_credential_rules

    def split_while_old_writer_races(conn=None):
        split(conn)
        with psycopg.connect(db.pools["data"].conninfo, autocommit=True) as other:
            other.execute("SET lock_timeout = '200ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                other.execute(
                    "UPDATE policies SET rules=%s::jsonb WHERE tenant_id=%s",
                    (json.dumps([old, block]), racing["id"]),
                )

    for read in (db.policy_version, db.get_policy):
        stored_before(racing["id"], [old, block])
        db._split_stored_credential_rules = split_while_old_writer_races
        try:
            read(racing["id"])
        finally:
            del db._split_stored_credential_rules
        assert not store_legacy(db.get_policy(racing["id"]))
    # Heartbeats scan the rules once per version, and an older server's save,
    # which bumps the version, is scanned and split.
    steady = tenant(db)
    db.save_policy(steady["id"], [block])
    scans, one = [], db.one
    db.one = lambda q, *a, **k: (scans.append(q) if "@>" in q else None) or one(q, *a, **k)
    try:
        version = db.policy_version(steady["id"])
        assert db.policy_version(steady["id"]) == version and len(scans) == 1
        db.execute(
            "UPDATE policies SET rules=$2::jsonb, version=version+1 WHERE tenant_id=$1",
            steady["id"], json.dumps([old, block]),
        )
        assert db.policy_version(steady["id"]) == version + 2
    finally:
        del db.one
    assert not store_legacy(db.get_policy(steady["id"]))
    # A legacy copy without an id keeps other rules' ask state.
    anonymous = tenant(db)
    stored_before(anonymous["id"], [{k: v for k, v in old.items() if k != "id"},
                                    dict(block, action="deny")], asks=[block["id"]])
    db.execute(migration.read_text())
    rules = db.get_policy(anonymous["id"])["rules"]
    assert action(rules, ssh) == "ask" and len({r["id"] for r in rules}) == 4
    # Reading a policy that is already split keeps its stored order, which
    # sensors holding its version enforce.
    kept = tenant(db)
    warned = [r for r in default_policy_rules() if r["match"].get("path_glob") in CREDENTIAL_GLOBS]
    stored_before(kept["id"], [*warned, block])
    assert [r["id"] for r in db.get_policy(kept["id"])["rules"]] == [r["id"] for r in [*warned, block]]
    # A copy changed to allow goes last too, behind the deny that decided.
    allowed = tenant(db)
    stored_before(allowed["id"], [dict(old, action="allow"), block])
    db.execute(migration.read_text())
    rules = db.get_policy(allowed["id"])["rules"]
    assert action(rules, ssh) == "deny" and action(rules, nested) == "allow"
    db.save_policy(allowed["id"], [dict(old, action="allow"), block])
    assert db.get_policy(allowed["id"])["rules"] == rules

    # A server rolled back past 0037 can write the legacy rule again; the next
    # start splits it without waiting for a policy save.
    rolled = tenant(db)
    version = stored_before(rolled["id"], [old, block])
    db.migrate()
    policy = db.get_policy(rolled["id"])
    assert policy["version"] == version + 1
    assert [r["match"]["path_glob"] for r in policy["rules"]] == [
        "**/.ssh/**", "**/.aws/**", "**/.ssh/**", "**/.kube/**",
    ]

    # A policy cached before the migration and saved back (a console left
    # open across the upgrade) is split on save. A copy changed to deny keeps
    # its place, so a later allow cannot overtake it.
    stale = tenant(db)
    home = {"id": "home", "name": "Allow home", "action": "allow", "enabled": True,
            "match": {"path_glob": "/home/a/**"}}
    db.save_policy(stale["id"], [dict(old, action="deny"), home, block])
    rules = db.get_policy(stale["id"])["rules"]
    assert [r["id"] for r in rules] == ["cred-aws", "cred-ssh", "cred-kube", "home", "block"]
    assert action(rules, ssh) == "deny" and action(rules, nested) == "deny"
    # A deny appended after already-split warnings still comes first.
    appended = tenant(db)
    db.save_policy(appended["id"], default_policy_rules())
    db.save_policy(appended["id"], db.get_policy(appended["id"])["rules"] + [block])
    assert action(db.get_policy(appended["id"])["rules"], ssh) == "deny"
