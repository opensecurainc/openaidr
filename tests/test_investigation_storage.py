"""Dormant complete-job DDL preserves retained investigation evidence."""

from pathlib import Path
import hashlib
import json

import pytest
from psycopg.errors import CheckViolation, ForeignKeyViolation, NotNullViolation
from psycopg.types.json import Jsonb

from openaidr.server import store
from openaidr.server.store import Conflict, new_id
from test_store import db, sensor, tenant  # noqa: F401


MIGRATION = "0142_complete_investigation_storage.sql"


@pytest.fixture
def legacy_db(request, tmp_path, monkeypatch):
    # Exercise this migration's predecessor schema independently of later DDL.
    directory = tmp_path / "migrations"
    directory.mkdir()
    for path in Path(store.__file__).with_name("migrations").glob("*.sql"):
        if int(path.name[:4]) < 142:
            (directory / path.name).symlink_to(path)
    source = Path(store.__file__).with_name("migrations") / MIGRATION
    monkeypatch.setattr(store, "__file__", str(tmp_path / "store.py"))
    result = request.getfixturevalue("db")
    (directory / MIGRATION).symlink_to(source)
    return result


def attempt(db, tid, *, protocol=None):
    sid = sensor(db, tid)[0]["id"]
    registration, snapshot, job, ident = [new_id() for _ in range(4)]
    db.execute("""INSERT INTO session_registrations(id,tenant_id,sensor_id,product,expires_at)
        VALUES($1,$2,$3,'codex-cli',now()+interval '1 hour')""", registration, tid, sid)
    db.execute("""INSERT INTO session_snapshots
        (id,tenant_id,sensor_id,registration_id,revision,input_version,lifecycle,coverage,counts)
        VALUES($1,$2,$3,$4,1,1,'incomplete','{}','{}')""", snapshot, tid, sid, registration)
    columns, values = (",protocol_version", ",$7") if protocol is not None else ("", "")
    args = (protocol,) if protocol is not None else ()
    db.execute(f"""INSERT INTO session_investigation_jobs
        (id,tenant_id,sensor_id,registration_id,snapshot_id,detector_config_version,settings_version,
         configuration,routing_reason{columns})
        VALUES($1,$2,$3,$4,$5,1,1,$6,'risk_threshold'{values})""",
        job, tid, sid, registration, snapshot, Jsonb({"retained": "configuration"}), *args)
    db.execute("""INSERT INTO session_investigation_attempts
        (id,job_id,tenant_id,ordinal,claim_token,worker_id,state,reserved_tokens,reserved_cost_usd,
         window_start,deadline_at)
        VALUES($1,$2,$3,1,$4,'storage-test','uncertain',100,0.12,now(),now()+interval '1 hour')""",
        ident, job, tid, new_id())
    return ident


def step(db, ident):
    sid = new_id()
    db.execute("""INSERT INTO session_investigation_steps
        (id,attempt_id,ordinal,kind,input_manifest,input_sha256,input_bytes)
        VALUES($1,$2,1,'chunk','{}',$3,2)""", sid, ident, "a" * 64)
    return sid


def read(db, ident, *, step_id=None, submission_id=None, call="read-1", legacy=False):
    rid = new_id()
    columns, values = ("", "") if legacy else (",submission_id", ",$6")
    args = () if legacy else (submission_id,)
    db.execute(f"""INSERT INTO session_investigation_reads
        (id,attempt_id,step_id,tool_call_id,tool_name,arguments,status,response,response_sha256{columns})
        VALUES($1,$2,$3,$4,'read_session','{{}}','delivered','{{}}',$5{values})""",
        rid, ident, step_id, call, "b" * 64, *args)
    return rid


def submission(db, ident, tid, *, request=None, api_tid=None):
    db.execute("""INSERT INTO session_investigation_submissions
        (attempt_id,tenant_id,origin,api_tenant_id,request,request_sha256)
        VALUES($1,$2,'https://intelligence.example.test',$3,$4,$5)""",
        ident, tid, api_tid or tid, json.dumps(request if request is not None else {"request_id": ident}), "c" * 64)


def schema(db, table):
    return db.many("""SELECT column_name,column_default,is_nullable FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name=$1 ORDER BY ordinal_position""", table)


def test_upgrade_preserves_retained_rows_defaults_and_protocol(legacy_db):
    db = legacy_db
    tid = tenant(db)["id"]
    ident = attempt(db, tid)
    sid = step(db, ident)
    read(db, ident, step_id=sid, legacy=True)
    db.execute("""INSERT INTO session_investigation_remote_bindings
        (attempt_id,tenant_id,owner_tenant_id,origin,profile,create_request,remote_id)
        VALUES($1,$2,$2,'https://retained.example.test','{"profile":"original"}','{}',$3)""", ident, tid, new_id())
    db.execute("""INSERT INTO session_investigation_remote_messages
        (id,attempt_id,step_id,kind,message,message_sha256)
        VALUES($1,$2,$3,'step','{"retained":"message"}',$4)""", new_id(), ident, sid, "d" * 64)
    db.execute("""INSERT INTO session_investigation_requests
        (id,attempt_id,step_id,ordinal,input_sha256,request_sha256,input_tokens_counted,max_output_tokens,
         reserved_tokens,reserved_cost_usd,price_quote,usage_id)
        VALUES($1,$2,$3,1,$4,$5,10,90,100,0.12,'{"retained":"quote"}',$6)""",
        new_id(), ident, sid, "a" * 64, "f" * 64, new_id())
    db.execute("""INSERT INTO service_credit_receipts(tenant_id,request_id,origin,api_tenant_id,service,state)
        VALUES($1,$2,'https://retained.example.test',$1,'investigations','disabled')""", tid, ident)
    db.execute("""INSERT INTO service_call_intents
        (tenant_id,request_id,origin,api_tenant_id,service,request_sha256,scope_id,attempt)
        VALUES($1,$2,'https://retained.example.test',$1,'investigations',$3,$4,1)""", tid, ident, "e" * 64, new_id())
    tables = ("tenant_session_detection_settings", "session_investigation_jobs", "session_investigation_attempts",
              "session_investigation_steps", "session_investigation_reads", "session_investigation_remote_bindings",
              "session_investigation_remote_messages", "session_investigation_requests",
              "service_credit_receipts", "service_call_intents")
    retained = {table: db.many(f"SELECT * FROM {table}") for table in tables}
    settings_schema = schema(db, tables[0])
    budgets = schema(db, "session_investigation_attempts")
    assert db.migrate() == [MIGRATION]
    assert db.migrate() == []
    for table, rows in retained.items():
        actual = db.many(f"SELECT * FROM {table}")
        assert [{key: row[key] for key in rows[0]} for row in actual] == rows
    assert schema(db, tables[0])[:len(settings_schema)] == settings_schema
    assert schema(db, "session_investigation_attempts")[:len(budgets)] == budgets
    assert db.scalar("SELECT protocol_version FROM session_investigation_jobs") == 1
    assert db.scalar("SELECT count(*) FROM session_investigation_submissions") == 0
    # New legacy writers still omit the protocol and credit fields.
    new_tid = tenant(db)["id"]
    new_attempt = attempt(db, new_tid)
    new_settings = db.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", new_tid)
    for field in ("version", "detector_config_version", "model", "max_tokens_per_attempt",
                  "max_cost_usd_per_attempt", "hourly_tokens", "hourly_cost_usd"):
        assert new_settings[field] == retained[tables[0]][0][field]
    assert db.scalar("SELECT protocol_version FROM session_investigation_jobs WHERE tenant_id=$1", new_tid) == 1
    with pytest.raises(NotNullViolation):
        db.execute("UPDATE session_investigation_attempts SET reserved_tokens=NULL WHERE id=$1", new_attempt)


def test_missing_lower_migration_applies_after_storage(db):
    # All applied versions, rather than a maximum-version watermark, govern
    # upgrades when independently merged migrations arrive out of order.
    db.execute("DROP TABLE service_call_intents,service_credit_receipts")
    db.execute("DELETE FROM schema_migrations WHERE version=140")
    assert db.scalar("SELECT max(version) FROM schema_migrations") >= 142
    assert db.migrate() == ["0140_service_credit_storage.sql"]
    assert db.migrate() == []
    assert db.scalar("SELECT count(*) FROM service_credit_receipts") == 0
    assert db.scalar("SELECT count(*) FROM service_call_intents") == 0


def test_submission_identity_tenant_binding_and_recovery_metadata(db):
    tid, other = tenant(db)["id"], tenant(db)["id"]
    ident = attempt(db, tid, protocol=4)
    for value in ({}, {"request_id": None}, {"request_id": new_id()}, []):
        with pytest.raises(CheckViolation):
            submission(db, ident, tid, request=value)
    with pytest.raises(CheckViolation):
        submission(db, ident, tid, api_tid=other)
    with pytest.raises(ForeignKeyViolation):
        submission(db, ident, other)
    submission(db, ident, tid)
    for assignment in ("origin='https://other.example.test'", "request='{}'", "request_sha256=repeat('d',64)",
                       "remote_id=gen_random_uuid()", "remote_status='unknown'"):
        with pytest.raises(CheckViolation):
            db.execute(f"UPDATE session_investigation_submissions SET {assignment} WHERE attempt_id=$1", ident)
    db.execute("""UPDATE session_investigation_submissions SET remote_id=attempt_id,remote_status='running',
        cancel_requested=true,checked_at=now(),last_error='poll unavailable' WHERE attempt_id=$1""", ident)
    with pytest.raises(CheckViolation):
        db.execute("UPDATE session_investigation_submissions SET remote_id=NULL WHERE attempt_id=$1", ident)
    with pytest.raises(CheckViolation):
        db.execute("UPDATE session_investigation_jobs SET protocol_version=1 WHERE tenant_id=$1", tid)
    saved = db.one("SELECT * FROM session_investigation_submissions WHERE attempt_id=$1", ident)
    assert saved["remote_id"] == ident and saved["cancel_requested"]
    # Expired service output may close local recovery without rewriting the
    # accepted identity, request hash or mirrored billing.
    db.execute("""UPDATE session_investigation_submissions SET remote_status='completed',
        closed_at=now(),last_error='result_expired' WHERE attempt_id=$1""", ident)
    current = db.one("SELECT * FROM session_investigation_submissions WHERE attempt_id=$1", ident)
    for field in ("request", "request_sha256", "origin", "api_tenant_id", "remote_id"):
        assert current[field] == saved[field]


def test_submission_reads_need_no_steps_and_keep_evidence_immutable(db):
    tid = tenant(db)["id"]
    ident = attempt(db, tid, protocol=4)
    other = attempt(db, tid, protocol=4)
    submission(db, ident, tid)
    submission(db, other, tid)
    rid = read(db, ident, submission_id=ident)
    assert db.scalar("SELECT count(*) FROM session_investigation_steps") == 0
    assert db.scalar("SELECT submission_id FROM session_investigation_reads WHERE id=$1", rid) == ident
    with pytest.raises(Conflict):
        read(db, ident, submission_id=ident)
    for options in ({}, {"submission_id": other}, {"step_id": step(db, ident), "submission_id": ident}):
        with pytest.raises(CheckViolation):
            read(db, ident, call="invalid", **options)
    with pytest.raises(CheckViolation):
        db.execute("UPDATE session_investigation_reads SET response=$2 WHERE id=$1", rid, Jsonb({"changed": True}))
    legacy = attempt(db, tid)
    legacy_read = read(db, legacy, step_id=step(db, legacy))
    assert db.scalar("SELECT submission_id IS NULL FROM session_investigation_reads WHERE id=$1", legacy_read)
    with pytest.raises(ForeignKeyViolation):
        read(db, other, call="foreign-step", step_id=db.scalar(
            "SELECT step_id FROM session_investigation_reads WHERE id=$1", legacy_read))
    db.execute("DELETE FROM session_investigation_attempts WHERE id=$1", ident)
    assert db.scalar("SELECT count(*) FROM session_investigation_submissions WHERE attempt_id=$1", ident) == 0
    assert db.scalar("SELECT count(*) FROM session_investigation_reads WHERE id=$1", rid) == 0
    assert db.scalar("SELECT count(*) FROM session_investigation_reads WHERE id=$1", legacy_read) == 1


def test_credit_storage_bounds_preserve_disabled_and_zero(db):
    tid = tenant(db)["id"]
    ident = attempt(db, tid)
    for per_attempt, hourly in ((None, 1), (1, None), (2, 1), (-1, 1), (0, 9007199254740992)):
        with pytest.raises(CheckViolation):
            db.execute("""UPDATE tenant_session_detection_settings SET max_credits_per_attempt_microcredits=$2,
                hourly_credits_microcredits=$3 WHERE tenant_id=$1""", tid, per_attempt, hourly)
    for amount in (-1, 9007199254740992):
        with pytest.raises(CheckViolation):
            db.execute("UPDATE session_investigation_attempts SET reserved_credits_microcredits=$2 WHERE id=$1", ident, amount)
    db.execute("""UPDATE tenant_session_detection_settings SET max_credits_per_attempt_microcredits=0,
        hourly_credits_microcredits=0 WHERE tenant_id=$1""", tid)
    db.execute("UPDATE session_investigation_attempts SET reserved_credits_microcredits=0,credit_rate_version='test' WHERE id=$1", ident)
    assert db.scalar("SELECT reserved_credits_microcredits FROM session_investigation_attempts WHERE id=$1", ident) == 0


@pytest.mark.parametrize("number", [1e20, -0.0])
def test_request_canonical_bytes_survive_postgres(db, number):
    tid = tenant(db)["id"]
    ident = attempt(db, tid, protocol=4)
    raw = json.dumps({"request_id": ident, "body": {"number": number}}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode()).hexdigest()
    db.execute("""INSERT INTO session_investigation_submissions
        (attempt_id,tenant_id,origin,api_tenant_id,request,request_sha256)
        VALUES($1,$2,'https://intelligence.example.test',$2,$3,$4)""", ident, tid, raw, digest)
    row = db.one("SELECT request,request_sha256 FROM session_investigation_submissions WHERE attempt_id=$1", ident)
    # The original canonical representation is the retry identity, including
    # exponent notation and the sign of zero. JSONB normalizes these numbers.
    actual = row["request"]
    assert actual == raw
    assert hashlib.sha256(actual.encode()).hexdigest() == row["request_sha256"] == digest
