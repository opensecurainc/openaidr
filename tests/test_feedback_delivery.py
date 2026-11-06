"""Feedback sharing through HTTP and PostgreSQL with an isolated remote service."""

import copy
import json
from datetime import datetime, timezone

import httpx
import pytest

from openaidr.server import feedback_delivery as delivery
from openaidr.server.config import Config
from openaidr.server.desktop_guardrails import review_request
from openaidr.server.store import new_id
from test_desktop_guardrails import record
from test_hook_policy import system as system, browser
from test_store import db as db, tenant, sensor

ORIGIN = "https://intelligence.example.test"
TOKEN = "oati_" + "1" * 32 + "." + "x" * 43
pytestmark = pytest.mark.usefixtures("intelligence_environments")


def setup(db):
    tid = tenant(db)["id"]
    device, _, _ = sensor(db, tid)
    cfg = Config(database_url=db.url, tenant_id=tid, intelligence_origin=ORIGIN, intelligence_api_key=TOKEN)
    cfg.set_services("api")
    return tid, device, cfg


def configure(db, tid, cfg, scope="metadata"):
    return delivery.save(db, tid, dict(sharing_scope=scope, retention_days=7,
                         version=delivery.read(db, tid, cfg)["version"]), {}, cfg)


def review(db, device, ident=None, label="false_positive"):
    ident = ident or record(db, device)
    detail = review_request(db, device, "check", {"id": ident, "review_version": 1})
    return review_request(db, device, "review", dict(id=ident, label=label, note="PRIVATE NOTE",
        review_version=1, evidence_sha256=detail["evidence_sha256"],
        expected_revision=detail["review_revision"], request_id=new_id()))


@pytest.fixture
def remote(monkeypatch):
    original = httpx.AsyncClient
    requests, received, deleted = [], {}, set()
    state = {"status": 200, "supported": True, "interrupt": False}

    def handle(request):
        requests.append(request)
        if state["status"] != 200:
            return httpx.Response(state["status"], json={})
        if request.url.path == "/v1/capabilities":
            capabilities = {}
            if state["supported"]:
                capabilities["feedback"] = "configured"
            return httpx.Response(200, json=dict(tenant_id=state["tenant"], build="2026.10.30+2615786",
                capabilities=capabilities, provider_access="not_checked", investigation_worker="not_checked"))
        payload = json.loads(request.content)
        if request.url.path.endswith("/delete"):
            ident = request.url.path.split("/")[-2]
            deleted.add(ident)
            return httpx.Response(200, json=dict(schema_version=1, tenant_id=state["tenant"], feedback_id=ident,
                status="deleted", deleted_at=datetime.now(timezone.utc).isoformat()))
        key = (payload["feedback_id"], payload["revision"])
        if key in received:
            assert received[key][0] == payload
        else:
            receipt = dict(schema_version=1, tenant_id=state["tenant"], feedback_id=key[0], revision=key[1],
                receipt_id=new_id(), request_sha256=delivery.digest(payload),
                received_at=datetime.now(timezone.utc).isoformat(), expires_at=payload["expires_at"])
            received[key] = (copy.deepcopy(payload), receipt)
        if state["interrupt"]:
            raise KeyboardInterrupt("Simulated process loss after remote commit")
        return httpx.Response(200, json={**received[key][1], **state.get("receipt_changes", {})})

    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(**kwargs, transport=httpx.MockTransport(handle))
    monkeypatch.setattr(delivery.httpx, "AsyncClient", client)
    return state, requests, received, deleted


def test_opt_in_metadata_revision_order_and_retained_evidence(db, remote):
    tid, device, cfg = setup(db)
    state, requests, received, _ = remote
    state["tenant"] = tid
    old = review(db, device)
    assert not delivery.run_once(db, cfg) and not requests
    configure(db, tid, cfg)
    first = review(db, device)
    review(db, device, first["id"], "correct_denial")
    assert delivery.run_once(db, cfg) and delivery.run_once(db, cfg)
    assert list(received) == [(first["id"], 1), (first["id"], 2)]
    assert (old["id"], 1) not in received
    for payload, _ in received.values():
        assert payload["evidence"]["content"] is None and payload["note"] == ""
        assert payload["attribution"] == dict(kind="device", source_id=None, reviewer_id=None)
        assert "PRIVATE" not in json.dumps(payload)
        assert "content_not_shared" in payload["evidence"]["gaps"]
    assert db.scalar("SELECT count(*) FROM feedback_delivery WHERE payload IS NOT NULL") == 0
    assert db.scalar("SELECT count(*) FROM ordinary_hook_review_revisions WHERE check_id=$1", first["id"]) == 2


def test_evidence_upload_retry_and_lost_receipt_keep_one_snapshot(db, remote):
    tid, device, cfg = setup(db)
    state, _, received, _ = remote
    state["tenant"] = tid
    configure(db, tid, cfg, "evidence")
    value = review(db, device)
    state["status"] = 503
    assert delivery.run_once(db, cfg)
    queued = db.one("SELECT * FROM feedback_delivery")
    assert queued["status"] == "pending" and queued["attempts"] == 1
    assert not delivery.run_once(db, cfg)
    state.update(status=200, interrupt=True)
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    with pytest.raises(KeyboardInterrupt):
        delivery.run_once(db, cfg)
    assert db.scalar("SELECT attempts FROM feedback_delivery") == 2
    state["interrupt"] = False
    assert delivery.run_once(db, cfg)
    assert len(received) == 1 and received[(value["id"], 1)][0] == queued["payload"]
    assert "PRIVATE-ACTION" in json.dumps(received[(value["id"], 1)][0])
    assert db.scalar("SELECT status FROM feedback_delivery") == "sent"


def test_disable_withdraw_and_source_deletion_reconcile_remote_records(db, remote):
    tid, device, cfg = setup(db)
    state, _, received, deleted = remote
    state["tenant"] = tid
    configure(db, tid, cfg, "evidence")
    first = review(db, device)
    state["interrupt"] = True
    with pytest.raises(KeyboardInterrupt):
        delivery.run_once(db, cfg)
    configure(db, tid, cfg, "none")
    assert db.scalar("SELECT status FROM feedback_delivery") == "deleting"
    state["interrupt"] = False
    assert delivery.run_once(db, cfg) and first["id"] in deleted
    configure(db, tid, cfg, "evidence")
    second = review(db, device)
    assert delivery.run_once(db, cfg)
    db.execute("DELETE FROM ordinary_hook_checks WHERE id=$1", second["id"])
    assert delivery.run_once(db, cfg) and second["id"] in deleted
    assert len(received) == 2
    foreign = tenant(db)["id"]
    from openaidr.server.httpx import APIError
    with pytest.raises(APIError):
        delivery.withdraw(db, foreign, {"feedback_id": first["id"]}, {})
    assert db.scalar("SELECT count(*) FROM feedback_delivery WHERE payload IS NOT NULL") == 0


def test_unsupported_receiver_expired_credentials_and_destination_change(db, remote):
    tid, device, cfg = setup(db)
    state, requests, received, _ = remote
    state.update(tenant=tid, supported=False)
    configure(db, tid, cfg)
    review(db, device)
    assert delivery.run_once(db, cfg) and not received
    state["status"] = 401
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    assert delivery.run_once(db, cfg) and not received
    assert db.scalar("SELECT status FROM feedback_delivery") == "pending"
    count = len(requests)
    # A readable old credential must not send while the selected destination's
    # saved credential is unavailable.
    db.execute("INSERT INTO tenant_intelligence_selection(tenant_id,origin) VALUES($1,$2)", tid, "https://api.opensecura.ai")
    db.execute("INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,'corrupt')", tid, "https://api.opensecura.ai")
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    assert delivery.run_once(db, cfg) and len(requests) == count
    assert db.scalar("SELECT status FROM feedback_delivery") == "pending"
    db.execute("DELETE FROM tenant_intelligence_keys WHERE tenant_id=$1", tid)
    cfg.intelligence_origin = "https://api.opensecura.ai"
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    assert delivery.run_once(db, cfg) and len(requests) == count
    assert db.scalar("SELECT status FROM feedback_delivery") == "deleting"


def test_invalid_receipt_cannot_acknowledge_and_expiry_withdraws(db, remote):
    tid, device, cfg = setup(db)
    state, _, received, deleted = remote
    state.update(tenant=tid, receipt_changes={"request_sha256": "0" * 64})
    configure(db, tid, cfg)
    value = review(db, device)
    assert delivery.run_once(db, cfg) and len(received) == 1
    assert db.scalar("SELECT status FROM feedback_delivery") == "pending"
    # Retention ends while the remote acknowledgement remains unconfirmed.
    db.execute("UPDATE feedback_delivery SET expires_at=clock_timestamp()-interval '1 second',next_attempt_at=clock_timestamp()")
    state["receipt_changes"] = {}
    assert delivery.run_once(db, cfg) and value["id"] in deleted
    assert db.scalar("SELECT payload FROM feedback_delivery") is None


def test_unreadable_credential_keeps_cleanup_disable_and_retry_backoff(db, remote):
    from cryptography.fernet import Fernet

    tid, device, cfg = setup(db)
    state, requests, _, deleted = remote
    state.update(tenant=tid, status=503)
    configure(db, tid, cfg, "evidence")
    values = []
    for _ in range(3):
        values.append(review(db, device))
        assert delivery.run_once(db, cfg)
    cfg.intelligence_keys_key = Fernet.generate_key().decode()
    db.execute("INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,'corrupt')", tid, ORIGIN)
    db.execute("UPDATE feedback_delivery SET expires_at=clock_timestamp()-interval '1 second' WHERE feedback_id=$1", values[0]["id"])
    db.execute("DELETE FROM ordinary_hook_checks WHERE id=$1", values[1]["id"])
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    count = len(requests)
    for _ in range(3):
        assert delivery.run_once(db, cfg)
    assert len(requests) == count and not delivery.run_once(db, cfg)
    for value in values[:2]:
        row = db.one("SELECT * FROM feedback_delivery WHERE feedback_id=$1", value["id"])
        assert row["payload"] is None and row["status"] == "deleting"
    pending = db.one("SELECT * FROM feedback_delivery WHERE feedback_id=$1", values[2]["id"])
    assert pending["status"] == "pending" and pending["payload"] is not None
    assert db.scalar("SELECT count(*) FROM feedback_delivery WHERE error_code='delivery_unavailable' AND next_attempt_at>clock_timestamp()") == 3
    assert configure(db, tid, cfg, "none")["sharing_scope"] == "none"
    assert db.scalar("SELECT count(*) FROM feedback_delivery WHERE payload IS NOT NULL") == 0
    db.execute("DELETE FROM tenant_intelligence_keys WHERE tenant_id=$1", tid)
    db.execute("UPDATE feedback_delivery SET next_attempt_at=clock_timestamp()")
    state["status"] = 200
    for _ in range(3):
        assert delivery.run_once(db, cfg)
    assert deleted == {value["id"] for value in values}


def test_feedback_settings_require_admin_csrf_and_tenant_binding(system):
    cfg = system.client.app.state.service.cfg
    cfg.tenant_id, cfg.intelligence_origin, cfg.intelligence_api_key = system.tenant["id"], ORIGIN, TOKEN
    data = dict(sharing_scope="metadata", retention_days=7, version=0)
    for method, route, body in (("GET", "settings/feedback", None), ("PUT", "settings/feedback", data),
                               ("POST", "settings/feedback/withdraw", {"feedback_id": new_id()})):
        assert browser(system, method, route, body, user="viewer").status_code == 403
        assert system.client.request(method, "/api/v1/" + route, json=body,
                                     headers=system.headers["foreign"]).status_code == 403
    response = browser(system, "GET", "settings/feedback")
    assert response.status_code == 200 and response.json()["sharing_scope"] == "none"
    assert TOKEN not in response.text and response.headers["cache-control"] == "no-store"
    assert browser(system, "PUT", "settings/feedback", data).status_code == 200
    assert browser(system, "PUT", "settings/feedback", data).status_code == 409
    assert system.client.put("/api/v1/settings/feedback", json=data,
        headers={"Cookie": system.headers["admin"]["Cookie"]}).status_code == 403


def test_case_export_keeps_reviewed_attempt_and_independent_outcome(system, remote):
    from test_risk_cases import cases, investigate, report_attempt, verdict
    from test_ordinary_session_detection import configure as configure_detection

    st, tid = system.db, system.tenant["id"]
    cfg = system.client.app.state.service.cfg
    cfg.tenant_id, cfg.intelligence_origin, cfg.intelligence_api_key = tid, ORIGIN, TOKEN
    state, _, received, _ = remote
    state["tenant"] = tid
    configure(st, tid, cfg, "evidence")
    configure_detection(system)
    _, job = investigate(system)
    attempt = report_attempt(system, job)
    case = cases(system)["groups"]["sessions"]["items"][0]
    shown = cases(system, "/" + case["id"])
    saved = verdict(system, case, "fp", context=shown["review_context"])
    report_attempt(system, job, ordinal=2, report={"title": "Later", "summary": "Later evidence", "status": "no_finding", "findings": [], "gaps": []})
    assert delivery.run_once(st, cfg)
    payload = received[(case["id"], 1)][0]
    assert payload["feedback_type"] == "detection" and payload["label"] == "false_positive"
    assert payload["evidence"]["content"]["reports"][0]["attempt_id"] == attempt
    actor = st.get_session(system.headers["admin"]["Cookie"].split("=", 1)[1])["user"]["id"]
    assert payload["attribution"]["reviewer_id"] == actor
    verdict(system, saved["case"], "review")
    assert delivery.run_once(st, cfg)
    reopened = received[(case["id"], 2)][0]
    assert reopened["label"] == "under_review" and "legacy_unbound" in reopened["evidence"]["gaps"]
    assert st.scalar("SELECT count(*) FROM findings") == 0
