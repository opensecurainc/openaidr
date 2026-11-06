"""Real PostgreSQL migration, identity, and physical storage boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import timedelta
import os
import hashlib
import json
from pathlib import Path
import time

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb
import pytest

from openaidr.server import store
from openaidr.server.store import Store, Conflict, new_id, now
from test_telemetry_server import export


@pytest.fixture
def database(request):
    url = os.environ.get("OPENAIDR_TEST_DATABASE_URL")
    if not url:
        pytest.skip("OPENAIDR_TEST_DATABASE_URL not configured")
    schema = "partitions_" + new_id().replace("-", "")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    try:
        migration_state = getattr(request, "param", None)
        if migration_state in (49, 63, 153, "without_0045"):
            with st.transaction() as conn:
                conn.execute("CREATE TABLE schema_migrations (version int PRIMARY KEY, name text NOT NULL)")
                for path in sorted(Path(store.__file__).with_name("migrations").glob("*.sql")):
                    version = int(path.name.split("_")[0])
                    # Enrollment needs the independent sensor capability columns
                    # while the telemetry schema remains at the requested version.
                    if (isinstance(migration_state, int) and (version <= migration_state or version in (71, 74, 82, 89))) or (migration_state == "without_0045" and version != 45):
                        conn.execute(path.read_text())
                        conn.execute("INSERT INTO schema_migrations VALUES (%s,%s)", (version, path.name))
        else:
            st.migrate()
        bootstrap = st.bootstrap_tenant("Partitions", "partitions")
        sensor, _, _ = st.enroll_sensor({"enrollment_token": bootstrap["enrollment_token"], "hostname": "test"})
        yield st, sensor
    finally:
        st.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.mark.parametrize("database", [49], indirect=True)
def test_populated_migration_preserves_rows_links_indexes_and_retries(database):
    st, sensor = database
    batch, exported, event = new_id(), new_id(), new_id()
    stamp = now() - timedelta(days=35)
    payload = export("metrics")
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False).encode()).hexdigest()
    st.execute("""INSERT INTO telemetry_exports
        (id,tenant_id,sensor_id,signal,batch_id,payload_sha256,record_count,payload,received_at)
        VALUES ($1,$2,$3,'metrics',$4,$5,1,$6,$7)""",
        exported, sensor["tenant_id"], sensor["id"], batch, digest, Jsonb(payload), stamp)
    st.execute("""INSERT INTO events
        (id,tenant_id,sensor_id,time,kind,product,body,export_id,received_at)
        VALUES ($1,$2,$3,$4,'sensor','codex-cli',$5,$6,$4)""",
        event, sensor["tenant_id"], sensor["id"], stamp, Jsonb({"kind": "sensor"}), exported)
    before = {table: st.many(f"SELECT to_jsonb(t) AS row FROM {table} t") for table in ("events", "telemetry_exports")}
    assert st.migrate() == [path.name for path in sorted(Path(store.__file__).with_name("migrations").glob("*.sql"))
                            if int(path.name.split("_")[0]) > 49 and int(path.name.split("_")[0]) not in (71, 74, 82, 89)]
    assert st.migrate() == []
    for name in ("events_hook_request_idx", "events_hook_check_idx", "events_hook_delivery_idx"):
        assert st.scalar("SELECT indisvalid FROM pg_index WHERE indexrelid=$1::regclass", name)
    for table, rows in before.items():
        after = st.many(f"SELECT to_jsonb(t) AS row FROM {table} t")
        assert after[0]["row"].pop("storage_day") == stamp.date().isoformat()
        assert after == rows
        assert st.scalar(f"SELECT relkind FROM pg_class WHERE oid='{table}'::regclass") == "p"
        assert st.scalar(f"SELECT tableoid::regclass::text FROM {table}").endswith(stamp.strftime("%Y%m%d"))
    assert not st.ingest_telemetry(sensor, "metrics", batch, payload, 1)
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 1
    assert st.ingest_telemetry(sensor, "metrics", new_id(), payload, 1)
    st.execute("DELETE FROM telemetry_exports WHERE id=$1", exported)
    assert st.scalar("SELECT export_id FROM events WHERE id=$1", event) is None
    assert not st.scalar("SELECT EXISTS(SELECT 1 FROM telemetry_export_keys WHERE id=$1)", exported)


@pytest.mark.parametrize("database", ["without_0045"], indirect=True)
def test_hook_assessment_migration_applies_after_partitioning(database):
    st, sensor = database
    event = new_id()
    st.execute("""INSERT INTO events (id,tenant_id,sensor_id,time,kind,product,body)
        VALUES ($1,$2,$3,now(),'prompt','codex-cli',$4)""",
        event, sensor["tenant_id"], sensor["id"], Jsonb({"text": "Review this change"}))
    assert st.migrate() == ["0045_ordinary_hook_assessments.sql"]
    assert st.migrate() == []
    assert st.scalar("SELECT body->>'text' FROM events WHERE id=$1", event) == "Review this change"
    for name in ("events_hook_request_idx", "events_hook_check_idx"):
        assert st.scalar("SELECT indisvalid FROM pg_index WHERE indexrelid=$1::regclass", name)
    assert st.ingest_batch(sensor, [{"id": new_id(), "time": now().isoformat(), "kind": "sensor"}])["accepted"] == 1


@pytest.mark.parametrize("database", [153], indirect=True)
def test_receipt_projection_backfill_updates_future_partitions_and_deletion(database):
    st, sensor = database
    request = new_id()
    body = {"source": {"collector": "hook-delivery", "hook_request_id": request},
            "hook": {"delivery_status": "delivered", "delivered_decision": "allow"}}
    valid = new_id()
    malformed = ["invalid", request.upper(), request.replace("-", ""), "x" * 10000]
    def insert(ident, payload, day=None):
        st.execute("""INSERT INTO events(id,tenant_id,sensor_id,time,kind,product,body,storage_day)
            VALUES($1,$2,$3,now(),'sensor','claude-code',$4,COALESCE($5,CURRENT_DATE))""",
            ident, sensor["tenant_id"], sensor["id"], Jsonb(payload), day)
    insert(valid, body)
    for value in malformed:
        insert(new_id(), {**body, "source": {**body["source"], "hook_request_id": value}})
    assert st.migrate() == [p.name for p in sorted(Path(store.__file__).with_name("migrations").glob("*.sql"))
                            if int(p.name.split("_")[0]) > 153]
    assert st.migrate() == []
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 1
    assert st.scalar("SELECT request_id FROM hook_delivery_events WHERE id=$1", valid) == request
    st.execute("UPDATE events SET product='codex-cli',received_at=now()-interval '1 day' WHERE id=$1", valid)
    assert st.one("SELECT product,received_at FROM hook_delivery_events WHERE id=$1", valid) == st.one(
        "SELECT product,received_at FROM events WHERE id=$1", valid)
    # An update can invalidate, replace, or restore a receipt without changing evidence identity.
    st.execute("UPDATE events SET kind='prompt' WHERE id=$1", valid)
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 0
    st.execute("UPDATE events SET kind='sensor' WHERE id=$1", valid)
    changed = {**body, "hook": {"delivery_status": "failed", "delivered_decision": "allow"}}
    st.execute("UPDATE events SET body=$2 WHERE id=$1", valid, Jsonb(changed))
    assert st.scalar("SELECT delivery_status FROM hook_delivery_events WHERE id=$1", valid) == "failed"
    st.execute("DELETE FROM events WHERE id=$1", valid)
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 0
    future, day = new_id(), now().date() + timedelta(days=20)
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    insert(future, body, day)
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 1
    # Retention removes the partition first, then retires identities in bounded batches.
    relation = st.scalar("SELECT tableoid::regclass::text FROM events WHERE id=$1", future)
    with st.transaction() as conn:
        conn.execute(psycopg.sql.SQL("DROP TABLE {}").format(psycopg.sql.Identifier(relation)))
        st.execute("UPDATE telemetry_partition_days SET retired_at=now() WHERE tenant_id=$1 AND storage_day=$2",
                   sensor["tenant_id"], day, conn=conn)
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 1
    from openaidr.server.telemetry_retention import _retire_keys
    with st.transaction() as conn:
        _retire_keys(st, sensor["tenant_id"], conn)
    assert st.scalar("SELECT count(*) FROM hook_delivery_events") == 0


@pytest.mark.parametrize("database", [153], indirect=True)
def test_decision_projection_upgrade_updates_and_retention(database):
    from openaidr.server.guardrail.analytics import stats
    from openaidr.server.telemetry_retention import _retire_keys

    st, sensor = database
    body = {"source": {"collector": "hook"}, "hook": {
        "decision": "deny", "rule_id": "r", "rule_name": "Original", "latency_ms": 1.5, "e2e_ms": 12}}
    variants = [body,
        {**body, "hook": {"decision": "allow"}},
        {**body, "hook": {"evaluated_decision": "warn", "returned_decision": "allow", "mode": "shadow",
                          "latency_ms": 3, "e2e_ms": 10**400}},
        {**body, "hook": {"decision": "deny", "failure_reason": "timeout", "latency_ms": -1, "e2e_ms": "bad"}},
        {**body, "source": {"collector": "otlp"}}]
    ids = [new_id() for _ in variants]
    def insert(ident, payload, day=None):
        st.execute("""INSERT INTO events(id,tenant_id,sensor_id,time,kind,product,body,storage_day)
            VALUES($1,$2,$3,now(),'hook.decision','claude-code',$4,COALESCE($5,CURRENT_DATE))""",
            ident, sensor["tenant_id"], sensor["id"], Jsonb(payload), day)
    for ident, payload in zip(ids, variants):
        insert(ident, payload)
    before = st.many("SELECT id,body FROM events ORDER BY id")
    assert st.migrate() == [p.name for p in sorted(Path(store.__file__).with_name("migrations").glob("*.sql"))
                            if int(p.name.split("_")[0]) > 153]
    assert st.migrate() == []
    assert st.many("SELECT id,body FROM events ORDER BY id") == before
    fields = {row.pop("id"): row for row in st.many(
        "SELECT id,decision,current,policy_ms,e2e_ms FROM guardrail_decision_events")}
    assert fields == dict(zip(ids[:4], [
        dict(decision="deny", current=True, policy_ms=1.5, e2e_ms=12),
        dict(decision="allow", current=False, policy_ms=None, e2e_ms=None),
        dict(decision="warn", current=True, policy_ms=3, e2e_ms=None),
        dict(decision=None, current=True, policy_ms=None, e2e_ms=None)]))
    totals = stats(st, sensor["tenant_id"], "1h")["totals"]
    assert (totals["total"], totals["deny"], totals["warn"], totals["legacy"]) == (2, 1, 1, 1)
    st.execute("UPDATE events SET time=now()-interval '2 hours' WHERE id=$1", ids[0])
    assert stats(st, sensor["tenant_id"], "1h")["totals"]["deny"] == 0
    st.execute("UPDATE events SET body=$2 WHERE id=$1", ids[0], Jsonb(variants[-1]))
    assert st.scalar("SELECT count(*) FROM guardrail_decision_events") == 3
    st.execute("UPDATE events SET body=$2 WHERE id=$1", ids[0], Jsonb(body))
    st.execute("DELETE FROM events WHERE id=$1", ids[0])
    assert st.scalar("SELECT count(*) FROM guardrail_decision_events") == 3
    future, day = new_id(), now().date() + timedelta(days=20)
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    insert(future, body, day)
    assert stats(st, sensor["tenant_id"], "1h")["totals"]["deny"] == 1
    relation = st.scalar("SELECT tableoid::regclass::text FROM events WHERE id=$1", future)
    with st.transaction() as conn:
        conn.execute(psycopg.sql.SQL("DROP TABLE {}").format(psycopg.sql.Identifier(relation)))
        st.execute("UPDATE telemetry_partition_days SET retired_at=now() WHERE tenant_id=$1 AND storage_day=$2",
                   sensor["tenant_id"], day, conn=conn)
    assert stats(st, sensor["tenant_id"], "1h")["totals"]["deny"] == 0
    assert st.scalar("SELECT count(*) FROM guardrail_decision_events WHERE id=$1", future) == 1
    with st.transaction() as conn:
        _retire_keys(st, sensor["tenant_id"], conn)
    assert st.scalar("SELECT count(*) FROM guardrail_decision_events WHERE id=$1", future) == 0


def test_duplicate_identity_across_days_tenants_and_concurrent_retries(database):
    st, sensor = database
    day = now().date() - timedelta(days=10)
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    event = {"id": new_id(), "time": now().isoformat(), "kind": "sensor"}
    assert st.ingest_batch(sensor, [event])["accepted"] == 1
    # The partition key does not weaken UUID uniqueness or tenant ownership.
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        st.execute("""INSERT INTO events (id,tenant_id,sensor_id,time,kind,product,body,storage_day)
            VALUES ($1,$2,$3,now(),'sensor','',$4,$5)""",
            event["id"], sensor["tenant_id"], sensor["id"], Jsonb(event), day)
    other = st.bootstrap_tenant("Other", "other")["tenant"]["id"]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        st.execute("""INSERT INTO events (id,tenant_id,sensor_id,time,kind,product,body)
            VALUES ($1,$2,$3,now(),'sensor','',$4)""",
            event["id"], other, sensor["id"], Jsonb(event))
    with pytest.raises(psycopg.errors.CheckViolation):
        st.execute("UPDATE events SET storage_day=$2 WHERE id=$1", event["id"], day)
    assert st.ingest_batch(sensor, [event])["duplicates"] == 1

    batch, payload = new_id(), export("logs")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda value: st.ingest_telemetry(sensor, "logs", value, payload, 1),
                                [batch, batch.upper(), batch, batch.upper()]))
    assert sorted(results) == [False, False, False, True]
    with pytest.raises(Conflict):
        st.ingest_telemetry(sensor, "logs", batch, export("logs", "changed"), 1)
    # A direct SQL write is also subject to global batch identity constraints.
    with pytest.raises(Conflict):
        st.execute("""INSERT INTO telemetry_exports
            (id,tenant_id,sensor_id,signal,batch_id,payload_sha256,record_count,payload,storage_day)
            VALUES ($1,$2,$3,'logs',$4,'different',1,'{}',$5)""",
            new_id(), sensor["tenant_id"], sensor["id"], batch, day)
    assert st.scalar("SELECT count(*) FROM telemetry_exports") == 1


def test_partition_drop_releases_files_and_preserves_another_tenant(database):
    st, sensor = database
    day = now().date() - timedelta(days=40)
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    event = new_id()
    st.execute("""INSERT INTO events (id,tenant_id,sensor_id,time,kind,product,body,storage_day)
        VALUES ($1,$2,$3,now(),'sensor','',$4,$5)""", event, sensor["tenant_id"], sensor["id"],
        Jsonb({"data": os.urandom(200000).hex()}), day)
    other = st.bootstrap_tenant("Other", "other")
    remote, _, _ = st.enroll_sensor({"enrollment_token": other["enrollment_token"], "hostname": "other"})
    st.ingest_batch(remote, [{"id": new_id(), "time": now().isoformat(), "kind": "sensor"}])
    relation = st.scalar("SELECT tableoid::regclass::text FROM events WHERE id=$1", event)
    files = st.many("""SELECT pg_relation_filepath(oid) AS path FROM pg_class
        WHERE oid=$1::regclass OR oid=(SELECT reltoastrelid FROM pg_class WHERE oid=$1::regclass)""", relation)
    assert st.scalar("SELECT pg_total_relation_size($1::regclass)", relation) > 200000
    for file in files:
        assert st.scalar("SELECT (pg_stat_file($1,true)).size", file["path"]) is not None
    with st.transaction() as conn:
        conn.execute(psycopg.sql.SQL("DROP TABLE {}").format(psycopg.sql.Identifier(relation)))
        st.execute("DELETE FROM event_keys WHERE tenant_id=$1 AND storage_day=$2",
                   sensor["tenant_id"], day, conn=conn)
    for file in files:
        # PostgreSQL can retain a zero-length file until the next checkpoint.
        assert st.scalar("SELECT (pg_stat_file($1,true)).size", file["path"]) in (None, 0)
    assert st.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", remote["tenant_id"]) == 1
    assert st.scalar("SELECT count(*) FROM events WHERE tenant_id=$1", sensor["tenant_id"]) == 0
    # Writes still work after a neighboring partition is removed.
    assert st.ingest_batch(sensor, [{"id": new_id(), "time": now().isoformat(), "kind": "sensor"}])["accepted"] == 1


@pytest.mark.parametrize("commit", [True, False])
@pytest.mark.parametrize("database", [63], indirect=True)
def test_concurrent_partition_provisioning_waits_for_commit_or_rollback(database, commit):
    st, sensor = database
    assert st.migrate() == [path.name for path in sorted(Path(store.__file__).with_name("migrations").glob("*.sql"))
                            if int(path.name.split("_")[0]) > 63 and int(path.name.split("_")[0]) not in (71, 74, 82, 89)]
    assert st.migrate() == []
    day = now().date() + timedelta(days=7)
    with ExitStack() as stack:
        blocker = stack.enter_context(psycopg.connect(st.url))
        workers = [stack.enter_context(psycopg.connect(st.url)) for _ in range(4)]
        blocker.execute("SELECT ensure_telemetry_partitions(%s,%s)", (sensor["tenant_id"], day))

        def provision(conn):
            conn.execute("SELECT ensure_telemetry_partitions(%s,%s)", (sensor["tenant_id"], day))
            conn.commit()

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(provision, conn) for conn in workers]
            try:
                deadline = time.monotonic() + 5
                while True:
                    waiting = st.scalar("""SELECT count(*) FROM pg_locks
                        WHERE locktype='advisory' AND NOT granted AND objid=684021562
                          AND pid=ANY($1)""", [conn.info.backend_pid for conn in workers])
                    if waiting == 4:
                        break
                    assert not any(future.done() for future in futures), "provisioning failed instead of waiting"
                    assert time.monotonic() < deadline, "provisioners did not wait for the lock"
                    time.sleep(0.01)
            finally:
                blocker.commit() if commit else blocker.rollback()
            for future in futures:
                future.result(timeout=5)

        assert st.scalar("""SELECT count(*) FROM telemetry_partition_days
            WHERE tenant_id=$1 AND storage_day IN ($2,$2+1)""", sensor["tenant_id"], day) == 2
        # Provisioned days bypass the global lock, even while another tenant owns it.
        blocker.execute("SELECT pg_advisory_xact_lock(684021562)")
        st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)


@pytest.mark.parametrize("lock", ["advisory", "table"])
def test_partition_provisioning_rolls_back_on_busy_lock_and_recovers(database, lock):
    st, sensor = database
    day = now().date() + timedelta(days=7)
    tenant_table = "telemetry_exports_" + sensor["tenant_id"].replace("-", "")
    with psycopg.connect(st.url) as blocker:
        blocker.execute("SELECT pg_advisory_xact_lock(684021560)")
        blocker.execute("SELECT pg_advisory_xact_lock(684021561)")
        st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day + timedelta(days=7))
    with psycopg.connect(st.url) as blocker:
        if lock == "advisory":
            blocker.execute("SELECT pg_advisory_xact_lock(684021562)")
        else:
            blocker.execute(psycopg.sql.SQL("LOCK TABLE {} IN ACCESS SHARE MODE").format(
                psycopg.sql.Identifier(tenant_table)))
        start = time.monotonic()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
        assert 0.9 <= time.monotonic() - start < 5
    assert not st.scalar("SELECT EXISTS(SELECT 1 FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day=$2)",
                         sensor["tenant_id"], day)
    for root in ("events", "telemetry_exports"):
        for bucket in (day, day + timedelta(days=1)):
            relation = root + "_" + sensor["tenant_id"].replace("-", "") + "_" + bucket.strftime("%Y%m%d")
            assert st.scalar("SELECT to_regclass($1)", relation) is None
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    st.execute("SELECT ensure_telemetry_partitions($1,$2)", sensor["tenant_id"], day)
    assert st.scalar("SELECT count(*) FROM telemetry_partition_days WHERE tenant_id=$1 AND storage_day IN ($2,$2+1)",
                     sensor["tenant_id"], day) == 2
