"""The local customer receipt mirror cannot invent or change API accounting."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from psycopg.errors import CheckViolation

from openaidr_api_client.client import Connection
from openaidr.server import service_billing
from openaidr.server.store import Conflict, new_id
from test_store import db, tenant  # noqa: F401


def test_receipt_identity_replay_and_terminal_accounting(db, intelligence_key):
    tid = tenant(db)["id"]
    connection = Connection("https://intelligence.example.test", intelligence_key, tid)
    ident = new_id()
    value = dict(request_id=ident, service="investigations", state="reserved", credits_reserved="0.12",
                 credits_charged=None, rate_version="test-v1")

    def record(receipt=value, **kwargs):
        return service_billing.record(db, tid, connection, receipt, request_id=ident,
                                      service="investigations", max_credits="0.12", **kwargs)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(item == value for item in pool.map(lambda _: record(), range(8)))
    assert db.scalar("SELECT count(*) FROM service_credit_receipts") == 1
    for override in ({"request_id": new_id()}, {"service": "assistant"}, {"credits_reserved": "0.13"},
                     {"credits_reserved": "0.11"}, {"rate_version": "test-v2"}):
        with pytest.raises(ValueError):
            record({**value, **override})
    # Retained SDKs reject unknown fields; customer SDKs discard them.
    try:
        sanitized = record({**value, "provider": "private"})
    except ValueError:
        pass
    else:
        assert sanitized == value
    with pytest.raises(ValueError, match="tenant"):
        service_billing.record(db, tid, replace(connection, tenant_id=new_id()), value,
                               request_id=ident, service="investigations")
    with pytest.raises(ValueError, match="immutable"):
        service_billing.record(db, tid, replace(connection, origin="https://other.example.test"), value,
                               request_id=ident, service="investigations")
    other = tenant(db)["id"]
    service_billing.record(db, other, replace(connection, tenant_id=other), value,
                           request_id=ident, service="investigations")
    assert db.scalar("SELECT count(*) FROM service_credit_receipts WHERE request_id=$1", ident) == 2
    pending = {**value, "state": "pending"}
    record(pending)
    with pytest.raises(ValueError):
        record(value)
    settled = {**value, "state": "settled", "credits_charged": "0.12"}
    assert record(settled) == settled
    assert record(settled) == settled
    with pytest.raises(ValueError):
        record({**value, "state": "released", "credits_charged": "0"})
    row = db.one("SELECT * FROM service_credit_receipts WHERE tenant_id=$1 AND request_id=$2", tid, ident)
    assert row["reserved_microcredits"] == row["charged_microcredits"] == 120000
    assert service_billing.view(row) == settled


def test_disabled_and_released_receipts_keep_unknown_distinct_from_zero(db, intelligence_key):
    tid = tenant(db)["id"]
    connection = Connection("https://intelligence.example.test", intelligence_key, tid)
    disabled = dict(request_id=new_id(), service="guardrail", state="disabled", credits_reserved=None,
                    credits_charged=None, rate_version=None)
    service_billing.record(db, tid, connection, disabled, request_id=disabled["request_id"], service="guardrail")
    assert service_billing.view(db.one("SELECT * FROM service_credit_receipts")) == disabled
    released = dict(request_id=new_id(), service="assistant", state="released", credits_reserved="1",
                    credits_charged="0", rate_version="rate-1")
    service_billing.record(db, tid, connection, released, request_id=released["request_id"], service="assistant")
    with pytest.raises(CheckViolation):
        db.execute("UPDATE service_credit_receipts SET charged_microcredits=NULL WHERE request_id=$1", released["request_id"])
    with pytest.raises(ValueError):
        service_billing.record(db, tid, connection, {**disabled, "state": "settled", "credits_reserved": "0",
                              "credits_charged": "0", "rate_version": "rate-1"}, request_id=disabled["request_id"], service="guardrail")


def test_receipt_mirror_participates_in_caller_transaction(db, intelligence_key):
    tid = tenant(db)["id"]
    connection = Connection("https://intelligence.example.test", intelligence_key, tid)
    value = dict(request_id=new_id(), service="guardrail", state="disabled", credits_reserved=None,
                 credits_charged=None, rate_version=None)
    with pytest.raises(RuntimeError, match="caller write failed"):
        with db.transaction() as conn:
            service_billing.record(db, tid, connection, value, request_id=value["request_id"],
                                   service="guardrail", conn=conn)
            raise RuntimeError("caller write failed")
    assert db.scalar("SELECT count(*) FROM service_credit_receipts WHERE tenant_id=$1", tid) == 0
    service_billing.record(db, tid, connection, value, request_id=value["request_id"], service="guardrail")
    assert service_billing.view(db.one("SELECT * FROM service_credit_receipts WHERE tenant_id=$1", tid)) == value


def test_intent_identity_and_unknown_completion_constraints(db):
    tid, other = tenant(db)["id"], tenant(db)["id"]
    scope, ident = new_id(), new_id()

    def insert(tenant_id=tid, request_id=ident):
        db.execute("""INSERT INTO service_call_intents
            (tenant_id,request_id,service,origin,api_tenant_id,request_sha256,scope_id,attempt)
            VALUES($1,$2,'guardrail','https://intelligence.example.test',$1,$3,$4,1)""",
            tenant_id, request_id, "a" * 64, scope)

    insert()
    assert db.scalar("SELECT outcome IS NULL AND completed_at IS NULL FROM service_call_intents")
    with pytest.raises(Conflict):
        insert(request_id=new_id())
    insert(tenant_id=other)
    for assignment in ("outcome='completed'", "completed_at=clock_timestamp()", "attempt=0",
                       "request_sha256='invalid'", "service='unknown'"):
        with pytest.raises(CheckViolation):
            db.execute(f"UPDATE service_call_intents SET {assignment} WHERE tenant_id=$1", tid)
    db.execute("""UPDATE service_call_intents SET outcome='failed',completed_at=clock_timestamp()
        WHERE tenant_id=$1""", tid)
    assert db.scalar("SELECT outcome FROM service_call_intents WHERE tenant_id=$1", tid) == "failed"
    assert db.scalar("SELECT outcome IS NULL FROM service_call_intents WHERE tenant_id=$1", other)


def test_additive_storage_upgrade_preserves_legacy_settings_and_accounting(db):
    # Recreate the current main database before applying only the new storage DDL.
    db.execute("DROP TABLE service_call_intents,service_credit_receipts")
    db.execute("DELETE FROM schema_migrations WHERE version=140")
    tid = tenant(db)["id"]
    usage_id = new_id()
    db.execute("""INSERT INTO model_usage(id,tenant_id,attempt,purpose,provider,model,status,cost_usd)
        VALUES($1,$2,1,'assistant','retained-provider','retained-model','completed',0.0123)""", usage_id, tid)
    saved_settings = db.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", tid)
    saved_usage = db.one("SELECT * FROM model_usage WHERE id=$1", usage_id)

    def settings_schema():
        return db.many("""SELECT column_name,column_default,is_nullable FROM information_schema.columns
            WHERE table_schema=current_schema() AND table_name='tenant_session_detection_settings'
            ORDER BY ordinal_position""")

    defaults = settings_schema()
    assert db.migrate() == ["0140_service_credit_storage.sql"]
    assert db.migrate() == []
    assert db.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", tid) == saved_settings
    assert db.one("SELECT * FROM model_usage WHERE id=$1", usage_id) == saved_usage
    assert settings_schema() == defaults
    assert db.scalar("SELECT count(*) FROM service_credit_receipts") == 0
    assert db.scalar("SELECT count(*) FROM service_call_intents") == 0
    # Existing writers still get their saved default model and budgets.
    new_tenant = tenant(db)["id"]
    current = db.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", new_tenant)
    for field in ("model", "max_tokens_per_attempt", "max_cost_usd_per_attempt", "hourly_tokens", "hourly_cost_usd"):
        assert current[field] == saved_settings[field]
