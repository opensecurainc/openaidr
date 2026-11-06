"""Existing runtime writers stop safely after another instance converts a tenant."""

import pytest

from openaidr.server import session_aggregation as aggregation
from test_session_aggregation import completed_session, detection_settings, finalized
from test_ordinary_session_detection import captured, finalize
from test_inline_guardrail import browser, system as system
from test_store import db as db  # noqa: F401


@pytest.mark.parametrize("managed", [True, False])
def test_current_finalizer_and_claimant_refuse_converted_tenant(system, managed):
    detection_settings(system, risk_threshold="0")
    value = completed_session(system, score=80) if managed else captured(system)
    run = lambda: finalized(system, value, enabled=True, ready=True) if managed else finalize(system, value)
    original = run()
    assert original["routing"]["status"] == "queued"
    jobs = system.db.many("SELECT * FROM session_investigation_jobs")
    system.db.execute("""UPDATE tenant_session_detection_settings SET job_protocol_version=4,
        max_credits_per_attempt_microcredits=2500000,hourly_credits_microcredits=20000000 WHERE tenant_id=$1""", system.tenant["id"])
    result = run()
    assert result["routing"]["status"] == "waiting_worker" and result["routing"]["job_id"] is None
    assert system.db.many("SELECT * FROM session_investigation_jobs") == jobs
    assert aggregation.claim_job(system.db, "old-worker", system.tenant["id"], worker_ready=True) is None
    assert system.db.scalar("SELECT count(*) FROM session_investigation_attempts") == 0
    assert browser(system, "PUT", "response/session-detection", {"enabled": True}).status_code == 409
    assert browser(system, "PUT", "response/session-detection", {"enabled": False}).status_code == 200
