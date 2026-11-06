"""MCP changes use real grants, tenant data, concurrency control, and audit writes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import time
from types import SimpleNamespace

import psycopg
import pytest

from openaidr.server import company_policy, dashboard_mcp_auth as auth, dashboard_mcp_changes as changes, hook_policy, session_aggregation
from openaidr.server.config import Config
from openaidr.server.httpx import APIError
from openaidr.server.store import new_id
from test_store import db  # noqa: F401


@pytest.fixture
def system(db):
    tenant = db.create_tenant("MCP changes", "mcp-" + new_id())
    user = db.create_user(tenant["id"], new_id() + "@example.test", "Analyst", "unused", "owner")
    principal = db.get_session(db.create_session(user["id"], tenant["id"]))
    cfg = Config(tenant_id=tenant["id"], public_url="https://tenant.example")
    cfg.dashboard_mcp_enabled = True
    auth.update_settings(db, cfg, principal, {"revision": 0, "enabled": True, "allowed_scopes": list(auth.SCOPE_IDS)})
    client = auth.create_client(db, cfg, principal, {
        "name": "Test client", "redirect_uris": ["https://client.example/callback"], "scopes": list(auth.SCOPE_IDS),
    })["client"]
    grant_id = new_id()
    db.execute("INSERT INTO dashboard_mcp_grants(tenant_id,id,client_id,user_id,scopes,resource,expires_at) "
               "VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+interval '1 hour')",
               tenant["id"], grant_id, client["id"], user["id"], list(auth.SCOPE_IDS), cfg.public_url + "/mcp")
    service = SimpleNamespace(st=db, cfg=cfg)
    grant = auth.validate_grant(db, cfg, grant_id)
    finding = new_id()
    db.execute("INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,sensor_id,primary_event_id,first_event_at) "
               "VALUES($1,$2,'test','secret_exfiltration','high','Evidence',$3,$4,clock_timestamp())",
               finding, tenant["id"], new_id(), new_id())
    return service, principal, grant, finding


def denied(status, call, *args, **kwargs):
    with pytest.raises(APIError) as exc:
        call(*args, **kwargs)
    assert exc.value.status == status, exc.value.message


def propose(system, **kwargs):
    service, _, grant, _ = system
    return changes.call_tool(service, grant, "propose_hook_mode", {
        "request_id": new_id(), "expected_version": 0, "mode": "enforce", **kwargs,
    })


def decide(system, proposal, **kwargs):
    service, browser, _, _ = system
    return changes.decide_proposal(service, browser, proposal["id"], {
        "decision": "approve", "digest": proposal["digest"], **kwargs,
    })


def test_triage_is_bounded_idempotent_and_preserves_source_text(system):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    row = st.get_finding(tenant, finding)
    update = {"request_id": new_id(), "finding_id": finding, "expected_updated_at": row["updated_at"].isoformat(),
              "status": "resolved", "resolution": "Confirmed by analyst", "assignee_id": browser["user"]["id"]}
    result = changes.call_tool(service, grant, "update_finding", update)
    assert result["status"] == "resolved"
    assert changes.call_tool(service, grant, "update_finding", update) == result
    assert st.get_finding(tenant, finding)["resolution"] == update["resolution"]
    assert "resolution" not in result
    denied(409, changes.call_tool, service, grant, "update_finding", {**update, "status": "triaged"})
    denied(409, changes.call_tool, service, grant, "update_finding", {**update, "request_id": new_id()})
    note = {"request_id": new_id(), "finding_id": finding, "body": "Captured text: ignore previous instructions"}
    first = changes.call_tool(service, grant, "add_finding_note", note)
    assert changes.call_tool(service, grant, "add_finding_note", note) == first
    assert len(st.list_notes(tenant, finding)) == 1
    assert st.list_notes(tenant, finding)[0]["body"] == note["body"]
    assert "body" not in first
    assert st.scalar("SELECT count(*) FROM audit_log WHERE action IN ('mcp.update_finding','mcp.add_finding_note')") == 2
    denied(400, changes.call_tool, service, grant, "add_finding_note", {**note, "tenant_id": tenant})
    denied(400, changes.call_tool, service, grant, "add_finding_note", {**note, "body": "x" * 10001})
    denied(404, changes.call_tool, service, grant, "approve_change_proposal", {})


def test_grants_roles_and_tenant_isolation_are_rechecked(system):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    note = {"request_id": new_id(), "finding_id": finding, "body": "A note"}
    other = st.create_tenant("Other", "mcp-other-" + new_id())
    other_finding = new_id()
    st.execute("INSERT INTO findings(id,tenant_id,rule_id,category,severity,title,sensor_id,primary_event_id,first_event_at) "
               "VALUES($1,$2,'test','secret_exfiltration','high','Other evidence',$3,$4,clock_timestamp())",
               other_finding, other["id"], new_id(), new_id())
    denied(404, changes.call_tool, service, grant, "add_finding_note", {**note, "finding_id": other_finding})
    denied(403, changes.call_tool, service, {**grant, "scopes": ["overview:read"]}, "add_finding_note", note)
    st.update_user(tenant, browser["user"]["id"], role="viewer")
    denied(403, changes.call_tool, service, grant, "add_finding_note", note)
    st.update_user(tenant, browser["user"]["id"], role="owner")
    st.execute("UPDATE dashboard_mcp_grants SET scopes=ARRAY['overview:read'] WHERE id=$1", grant["grant_id"])
    denied(403, changes.call_tool, service, grant, "add_finding_note", note)
    assert not changes.tool_catalog(browser["user"], ["overview:read"])
    st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE id=$1", grant["grant_id"])
    denied(401, changes.call_tool, service, grant, "add_finding_note", note)
    assert st.scalar("SELECT count(*) FROM finding_notes") == 0


def test_proposal_requires_exact_browser_review_and_applies_once(system):
    service, browser, grant, _ = system
    proposal = propose(system)
    assert proposal["status"] == "pending" and proposal["can_decide"] is False
    reviewed = changes.get_proposal(service, browser, proposal["id"])
    assert reviewed["before"] == {"mode": "shadow"} and reviewed["after"] == {"mode": "enforce"}
    assert hook_policy.get_settings(service.st, grant["tenant"]["id"])["mode"] == "shadow"
    assert changes.get_proposal(service, browser, proposal["id"])["can_decide"] is True
    assert changes.list_proposals(service, browser)["items"][0]["id"] == proposal["id"]
    denied(409, decide, system, proposal, digest="0" * 64)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: decide(system, proposal), range(2)))
    assert all(result["status"] == "applied" for result in results)
    settings = hook_policy.get_settings(service.st, grant["tenant"]["id"])
    assert settings["mode"] == "enforce" and settings["version"] == 1
    assert service.st.scalar("SELECT count(*) FROM audit_log WHERE action='mcp.change.applied'") == 1
    assert changes.call_tool(service, grant, "get_change_proposal", {"proposal_id": proposal["id"]})["status"] == "applied"
    denied(409, decide, system, proposal, decision="reject")
    service.st.execute("DELETE FROM dashboard_mcp_grants WHERE id=$1", grant["grant_id"])
    service.st.execute("DELETE FROM dashboard_mcp_clients WHERE id=$1", grant["client_id"])
    retained = changes.get_proposal(service, browser, proposal["id"])
    assert retained["status"] == "applied" and retained["client"]["name"] == "Test client"
    assert service.st.scalar("SELECT count(*) FROM audit_log WHERE action='mcp.change.applied'") == 1


def test_stale_expired_revoked_and_wrong_role_proposals_never_apply(system):
    service, browser, grant, _ = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = propose(system)
    hook_policy.save_settings(st, tenant, {"mode": "shadow", "version": 0}, {"id": browser["user"]["id"]})
    denied(409, decide, system, proposal)
    proposal = propose(system, expected_version=1)
    st.execute("UPDATE dashboard_mcp_changes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", proposal["id"])
    assert changes.get_proposal(service, browser, proposal["id"])["status"] == "expired"
    denied(409, decide, system, proposal)
    proposal = propose(system, expected_version=1)
    st.update_user(tenant, browser["user"]["id"], role="admin")
    denied(403, decide, system, proposal)
    st.update_user(tenant, browser["user"]["id"], role="owner")
    st.execute("UPDATE dashboard_mcp_grants SET revoked_at=clock_timestamp() WHERE id=$1", grant["grant_id"])
    denied(401, decide, system, proposal)
    rejected = decide(system, proposal, decision="reject")
    assert rejected["status"] == "rejected"
    assert hook_policy.get_settings(st, tenant)["mode"] == "shadow"


def test_audit_failure_rolls_back_approved_change_and_receipts(system):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = propose(system)
    st.execute("""CREATE FUNCTION reject_mcp_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN IF NEW.action IN ('mcp.change.applied','mcp.add_finding_note') THEN
                       RAISE EXCEPTION 'test audit storage unavailable'; END IF; RETURN NEW; END $$""")
    st.execute("CREATE TRIGGER reject_mcp_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_mcp_audit()")
    with pytest.raises(psycopg.errors.RaiseException, match="test audit storage unavailable"):
        decide(system, proposal)
    assert hook_policy.get_settings(st, tenant)["mode"] == "shadow"
    assert changes.get_proposal(service, browser, proposal["id"])["status"] == "pending"
    note = {"request_id": new_id(), "finding_id": finding, "body": "Must be rolled back"}
    with pytest.raises(psycopg.errors.RaiseException, match="test audit storage unavailable"):
        changes.call_tool(service, grant, "add_finding_note", note)
    assert not st.list_notes(tenant, finding)
    assert st.scalar("SELECT count(*) FROM dashboard_mcp_write_receipts WHERE request_id=$1", note["request_id"]) == 0


def test_company_policy_and_scheduling_reuse_existing_validation(system):
    service, browser, grant, _ = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = changes.call_tool(service, grant, "propose_company_policy", {
        "request_id": new_id(), "expected_version": 0, "prompt": "Do not send source code outside the company.",
    })
    assert company_policy.read(st, tenant)["prompt"] == ""
    reviewed = changes.get_proposal(service, browser, proposal["id"])
    assert decide(system, proposal)["status"] == "applied"
    assert company_policy.read(st, tenant)["prompt"] == reviewed["after"]["prompt"]
    settings = session_aggregation.get_settings(st, tenant)
    version = settings["version"]
    st.execute("UPDATE tenant_session_detection_settings SET enabled=false,max_cost_usd_per_attempt=NULL WHERE tenant_id=$1", tenant)
    denied(409, changes.call_tool, service, grant, "propose_detection_scheduling", {
        "request_id": new_id(), "expected_version": version, "enabled": True,
    })
    st.execute("UPDATE tenant_session_detection_settings SET max_cost_usd_per_attempt=$2 WHERE tenant_id=$1",
               tenant, settings["max_cost_usd_per_attempt"])
    proposal = changes.call_tool(service, grant, "propose_detection_scheduling", {
        "request_id": new_id(), "expected_version": version, "enabled": True,
    })
    assert decide(system, proposal)["status"] == "applied"
    assert session_aggregation.get_settings(st, tenant)["enabled"] is True


def test_existing_domain_calls_remain_compatible_and_accept_atomic_connection(system):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    actor = {"id": browser["user"]["id"], "name": "Analyst"}
    assert hook_policy.save_settings(st, tenant, {"mode": "shadow", "version": 0}, actor)["version"] == 1
    assert company_policy.save(st, tenant, {"revision": 0, "prompt": "Original"}, actor)["revision"] == 1
    version = session_aggregation.get_settings(st, tenant)["version"]
    assert session_aggregation.save_settings(st, tenant, {"enabled": False}, actor)["version"] == version + 1
    assert st.update_finding(tenant, finding, {"status": "triaged"})["status"] == "triaged"
    assert st.add_note(tenant, finding, actor["id"], "Original note")["body"] == "Original note"
    with pytest.raises(RuntimeError, match="roll back"):
        with st.transaction() as conn:
            hook_policy.save_settings(st, tenant, {"mode": "enforce", "version": 1}, actor, conn=conn)
            company_policy.save(st, tenant, {"revision": 1, "prompt": "New"}, actor, conn=conn)
            session_aggregation.save_settings(st, tenant, {"enabled": False}, actor, expected_version=version + 1, conn=conn)
            st.update_finding(tenant, finding, {"status": "open"}, conn=conn)
            st.add_note(tenant, finding, actor["id"], "Rolled back note", conn=conn)
            raise RuntimeError("roll back")
    assert hook_policy.get_settings(st, tenant)["mode"] == "shadow"
    assert company_policy.read(st, tenant)["prompt"] == "Original"
    assert session_aggregation.get_settings(st, tenant)["version"] == version + 1
    assert st.get_finding(tenant, finding)["status"] == "triaged"
    assert len(st.list_notes(tenant, finding)) == 1


def test_configuration_proposal_scope_never_discloses_policy_content(system):
    service, browser, grant, _ = system
    st, tenant = service.st, grant["tenant"]["id"]
    original = "Confidential policy: Project Falcon must remain inside the research team."
    company_policy.save(st, tenant, {"revision": 0, "prompt": original}, {"id": browser["user"]["id"]})
    st.execute("UPDATE dashboard_mcp_grants SET scopes=ARRAY['configuration:propose'] WHERE id=$1", grant["grant_id"])
    principal = {**grant, "scopes": ["configuration:propose"]}
    data = {"request_id": new_id(), "expected_version": 1, "prompt": "New policy proposal"}
    first = changes.call_tool(service, principal, "propose_company_policy", data)
    retry = changes.call_tool(service, principal, "propose_company_policy", data)
    status = changes.call_tool(service, principal, "get_change_proposal", {"proposal_id": first["id"]})
    for response in (first, retry, status):
        assert "before" not in response and "after" not in response
        assert original not in json.dumps(response) and data["prompt"] not in json.dumps(response)
        assert response["review_path"] == "/mcp/changes/" + first["id"]
    reviewed = changes.get_proposal(service, browser, first["id"])
    assert reviewed["before"] == {"prompt": original}
    assert reviewed["after"] == {"prompt": data["prompt"]}


def wait_for_blocked(st, blocker_pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if st.scalar("SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))", blocker_pid):
            return
        time.sleep(0.01)
    pytest.fail("the operation did not reach the expected database lock")


@pytest.mark.parametrize("expire", [False, True])
@pytest.mark.parametrize("wait_on", ["tenant", "user", "finding", "configuration", "note_audit", "approval_audit", "browser_audit"])
def test_authority_expiry_during_locks_cannot_authorize_or_commit(system, monkeypatch, wait_on, expire):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = propose(system)
    clock = [auth._now()]
    expires = clock[0] + timedelta(minutes=1)
    if wait_on == "browser_audit":
        st.execute("UPDATE auth_sessions SET expires_at=$2 WHERE id=$1", browser["session_id"], expires)
    else:
        st.execute("UPDATE dashboard_mcp_grants SET expires_at=$2 WHERE id=$1", grant["grant_id"], expires)
    monkeypatch.setattr(auth, "_now", lambda: clock[0])
    if wait_on.endswith("audit"):
        st.execute("""CREATE FUNCTION hold_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN IF NEW.action IN ('mcp.change.applied','mcp.add_finding_note') THEN
                           PERFORM pg_advisory_xact_lock(910252); END IF; RETURN NEW; END $$""")
        st.execute("CREATE TRIGGER hold_grant_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION hold_grant_audit()")
    request_id = new_id()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as conn:
            pid = st.scalar("SELECT pg_backend_pid()", conn=conn)
            if wait_on in ("tenant", "user", "finding"):
                table, ident = {"tenant": ("tenants", tenant), "user": ("tenant_users", browser["user"]["id"]),
                                "finding": ("findings", finding)}[wait_on]
                st.one("SELECT id FROM " + table + " WHERE id=$1 FOR UPDATE", ident, conn=conn)
            elif wait_on == "configuration":
                st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "hook-settings:" + tenant, conn=conn)
            else:
                st.execute("SELECT pg_advisory_xact_lock(910252)", conn=conn)
            if wait_on in ("tenant", "user"):
                future = pool.submit(auth.validate_grant, st, service.cfg, grant["grant_id"])
            elif wait_on in ("finding", "note_audit"):
                future = pool.submit(changes.call_tool, service, grant, "add_finding_note",
                                     {"request_id": request_id, "finding_id": finding, "body": "Grant-bound note"})
            else:
                future = pool.submit(decide, system, proposal)
            wait_for_blocked(st, pid)
            if expire:
                clock[0] = expires + timedelta(seconds=1)
        if expire:
            denied(401, future.result, timeout=5)
        else:
            assert future.result(timeout=5)
    changed_note = not expire and wait_on in ("finding", "note_audit")
    changed_policy = not expire and wait_on in ("configuration", "approval_audit", "browser_audit")
    assert len(st.list_notes(tenant, finding)) == int(changed_note)
    assert st.scalar("SELECT count(*) FROM dashboard_mcp_write_receipts WHERE request_id=$1", request_id) == int(changed_note)
    assert hook_policy.get_settings(st, tenant)["mode"] == ("enforce" if changed_policy else "shadow")
    assert st.scalar("SELECT status FROM dashboard_mcp_changes WHERE id=$1", proposal["id"]) == ("applied" if changed_policy else "pending")
    assert st.scalar("SELECT count(*) FROM audit_log WHERE action IN ('mcp.change.applied','mcp.add_finding_note')") == int(changed_note or changed_policy)


@pytest.mark.parametrize("invalidate", ["delete", "expire"])
def test_browser_session_is_rechecked_after_waiting_for_grant(system, invalidate):
    service, browser, grant, _ = system
    st = service.st
    proposal = propose(system)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as conn:
            pid = st.scalar("SELECT pg_backend_pid()", conn=conn)
            st.one("SELECT id FROM dashboard_mcp_grants WHERE id=$1 FOR UPDATE", grant["grant_id"], conn=conn)
            future = pool.submit(decide, system, proposal)
            wait_for_blocked(st, pid)
            if invalidate == "delete":
                st.execute("DELETE FROM auth_sessions WHERE id=$1", browser["session_id"])
            else:
                st.execute("UPDATE auth_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                           browser["session_id"])
        denied(401, future.result, timeout=5)
    assert hook_policy.get_settings(st, grant["tenant"]["id"])["mode"] == "shadow"
    assert st.scalar("SELECT status FROM dashboard_mcp_changes WHERE id=$1", proposal["id"]) == "pending"


def test_browser_expiry_is_rechecked_after_configuration_lock(system):
    service, browser, grant, _ = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = propose(system)
    st.execute("UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
               browser["session_id"])
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as conn:
            pid = st.scalar("SELECT pg_backend_pid()", conn=conn)
            st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "hook-settings:" + tenant, conn=conn)
            future = pool.submit(decide, system, proposal)
            wait_for_blocked(st, pid)
            while st.scalar("SELECT expires_at>clock_timestamp() FROM auth_sessions WHERE id=$1", browser["session_id"]):
                time.sleep(0.01)
        denied(401, future.result, timeout=5)
    assert hook_policy.get_settings(st, tenant)["mode"] == "shadow"


@pytest.mark.parametrize("operation", ["note", "approve"])
def test_elapsed_request_deadline_rolls_back_effects_and_audit(system, monkeypatch, operation):
    service, browser, grant, finding = system
    st, tenant = service.st, grant["tenant"]["id"]
    proposal = propose(system)
    deadline = time.monotonic() + 10000
    logical_time = [deadline - 1]
    monkeypatch.setattr(changes, "time", SimpleNamespace(monotonic=lambda: logical_time[0]))
    st.execute("""CREATE FUNCTION hold_mcp_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN IF NEW.action IN ('mcp.change.applied','mcp.add_finding_note') THEN
                       PERFORM pg_advisory_xact_lock(910251); END IF; RETURN NEW; END $$""")
    st.execute("CREATE TRIGGER hold_mcp_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION hold_mcp_audit()")
    request_id = new_id()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with st.transaction() as conn:
            pid = st.scalar("SELECT pg_backend_pid()", conn=conn)
            st.execute("SELECT pg_advisory_xact_lock(910251)", conn=conn)
            if operation == "note":
                future = pool.submit(changes.call_tool, service, {**grant, "mcp_deadline": deadline}, "add_finding_note",
                                     {"request_id": request_id, "finding_id": finding, "body": "Must roll back"})
            else:
                future = pool.submit(changes.decide_proposal, service, {**browser, "mcp_deadline": deadline}, proposal["id"],
                                     {"decision": "approve", "digest": proposal["digest"]})
            wait_for_blocked(st, pid)
            logical_time[0] = deadline + 1
        denied(503, future.result, timeout=5)
    assert not st.list_notes(tenant, finding)
    assert st.scalar("SELECT count(*) FROM dashboard_mcp_write_receipts WHERE request_id=$1", request_id) == 0
    assert hook_policy.get_settings(st, tenant)["mode"] == "shadow"
    assert st.scalar("SELECT status FROM dashboard_mcp_changes WHERE id=$1", proposal["id"]) == "pending"
    assert st.scalar("SELECT count(*) FROM audit_log WHERE action IN ('mcp.change.applied','mcp.add_finding_note')") == 0
