"""Context snapshots and action release through real PostgreSQL and HTTP."""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from openaidr.core.event import new_id
from openaidr.server import knowledge, knowledge_ingest
from test_approvals import approval_settings, consume, consume_body, decide
from test_inline_guardrail import browser, check, event, managed, payload, policy, system as system
from test_managed_foundation import Callback, ReceiverTransport, foundation, held
from test_session_aggregation import registered
from test_session_ownership import wait_for_blocker
from test_store import db as db


def publish(system, *, version="1", production=True):
    st, tenant = system.db, system.tenant["id"]
    current = knowledge_ingest.settings(st, tenant)
    if not current["enabled"]:
        knowledge.update(st, tenant, {"revision": current["revision"], "enabled": True})
    current = knowledge_ingest.settings(st, tenant)
    if current["retrieval_mode"] != "postgres":
        knowledge_ingest.set_mode(st, tenant, {"revision": current["revision"], "retrieval_mode": "postgres"})
    for ident, kind, scope, term, body in (
        ("omg", "command", "", "omg drain", "The omg drain operation drains a network zone."),
        ("zone", "resource", "account:core", "us-west-1",
         "In account core, us-west-1 is a " + ("production" if production else "development") + " network zone."),
    ):
        knowledge_ingest.import_source(st, tenant, {
            "revision": knowledge_ingest.settings(st, tenant)["revision"],
            "source_id": ident, "source_version": version, "title": ident,
            "source_uri": "wiki://reference/" + ident, "scope_key": scope,
            "markdown": body, "kind": kind,
            "keys": [{"key_type": "operation" if kind == "command" else "resource",
                      "lookup_value": term, "canonical_key": term}],
        })


def bind(system, registration, scope="account:core", **options):
    return browser(system, "PUT", f"session-registrations/{registration['id']}/context-scope",
                   {"scope_key": scope}, **options)


def request(system, registration, **options):
    return {**payload(system, registration, event(registration, command={"text": "omg drain us-west-1"}), **options),
            "context_version": 1}


def test_context_scope_is_admin_owned_and_missing_context_never_proves_safety(system):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
    publish(system)
    registration = managed(system)
    assert bind(system, registration, user="owner").status_code == 403
    assert bind(system, registration, user="foreign").status_code == 404
    for scope in ("account core", "a" * 241, "API_TOKEN=private-credential", "account:\u200bcore", "account:\x01core"):
        assert bind(system, registration, scope).status_code == 400
    missing = request(system, registration)
    missing["target"]["agent"]["account"] = "core"
    result = check(system, missing)
    assert result["decision"]["action"] == "block"
    assert "missing_scope" in result["assessment"]["knowledge"]["gaps"]
    legacy = request(system, registration)
    legacy.pop("context_version")
    assert check(system, legacy, expected=409)["error"]["code"] == "context_protocol_required"
    assert bind(system, registration).status_code == 200
    complete = check(system, request(system, registration))
    assert complete["decision"]["action"] == "allow"
    assert complete["assessment"]["knowledge"]["status"] == "matched"
    assert any("production" in doc["text"] for doc in complete["assessment"]["knowledge"]["documents"])
    assert consume(system, complete)["granted"] is True


@pytest.mark.parametrize("score", [0, 50])
def test_company_policy_changes_require_reassessment_before_release(system, score):
    approval_settings(system)
    registration = managed(system)
    system.provider.payload = system.provider.scored(score)
    value = payload(system, registration)
    first = check(system, value)
    if score:
        assert first["decision"]["action"] == "ask"
        decide(system, first["approval"]["id"])
    else:
        assert first["decision"]["action"] == "allow"
    saved = browser(system, "PUT", "response/company-policy", {
        "revision": 0, "prompt": "Require approval for production changes.",
    })
    assert saved.status_code == 200, saved.text
    assert consume(system, first, expected=409)["error"]["code"] == "context_changed"
    system.provider.payload = system.provider.scored(100)
    second_request = {**value, "request_id": new_id()}
    second = check(system, second_request)
    assert second["assessment_generation"] == 2
    assert second["assessment"]["company_policy"]["revision"] == 1
    assert second["decision"]["action"] == "block"
    assert consume(system, second, expected=409)["error"]["code"] == "action_blocked"
    assert check(system, value)["assessment"] == first["assessment"]
    assert browser(system, "PUT", "response/company-policy", {"revision": 1, "prompt": ""}).status_code == 200
    system.provider.payload = system.provider.scored(0)
    third = check(system, {**value, "request_id": new_id()})
    assert third["assessment_generation"] == 3
    assert third["assessment"]["company_policy"] == {"revision": 2}
    historical = check(system, second_request)
    assert historical["assessment"]["company_policy"] == {"revision": 1}
    assert "Require approval for production changes." not in json.dumps(historical)
    assert consume(system, third)["granted"]
    snapshots = system.db.many("SELECT company_policy FROM inline_guardrail_assessments ORDER BY generation")
    assert [row["company_policy"]["revision"] for row in snapshots] == [0, 1, 2]
    assert snapshots[1]["company_policy"]["prompt"] == "Require approval for production changes."
    assert len(system.provider.requests) == 3


def test_company_policy_edit_during_scoring_cannot_authorize_old_assessment(system):
    approval_settings(system)
    registration = managed(system)
    value = payload(system, registration)
    system.provider.block()
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(check, system, value)
        try:
            assert system.provider.entered.wait(5)
            assert browser(system, "PUT", "response/company-policy", {
                "revision": 0, "prompt": "Treat destructive actions as high risk.",
            }).status_code == 200
        finally:
            system.provider.release()
        previous = pending.result(timeout=5)
    assert previous["assessment"]["company_policy"]["revision"] == 0
    assert consume(system, previous, expected=409)["error"]["code"] == "context_changed"
    current = check(system, {**value, "request_id": new_id()})
    assert current["assessment_generation"] == 2
    assert current["assessment"]["company_policy"]["revision"] == 1
    assert consume(system, current)["granted"]


def test_reassessment_preserves_snapshots_and_never_repeats_a_consumed_action(system):
    approval_settings(system, context_enabled=True, context_required=True)
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    value = request(system, registration)
    first = check(system, value)
    sent = system.provider.requests[-1]["state"]
    snapshot = first["assessment"]["knowledge"]
    assert sent["prior_events"][-1]["tool"]["output"] == snapshot
    assert first["assessment_generation"] == 1
    alias = check(system, {**value, "request_id": new_id()})
    assert alias["assessment_generation"] == 1 and len(system.provider.requests) == 1
    publish(system, version="2", production=False)
    assert check(system, value)["assessment"]["knowledge"] == snapshot
    assert consume(system, first, expected=409)["error"]["code"] == "context_changed"
    second = check(system, {**value, "request_id": new_id()})
    assert second["assessment_generation"] == 2
    assert "development" in json.dumps(second["assessment"]["knowledge"])
    assert check(system, value)["assessment"] == first["assessment"]
    assert len(system.provider.requests) == 2
    assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 1
    assert system.db.scalar("SELECT count(*) FROM inline_guardrail_assessments") == 2
    assert system.db.many("SELECT attempt FROM model_usage ORDER BY attempt") == [{"attempt": 1}, {"attempt": 2}]
    session_id = system.db.scalar("SELECT id FROM agent_sessions WHERE registration_id=$1", registration["id"])
    path = f"sessions/{session_id}/guardrail-actions"
    actions = browser(system, "GET", path)
    assert actions.status_code == 200, actions.text
    action = actions.json()["items"][0]
    assert action["assessment"]["generation"] == 2
    decisions = browser(system, "GET", path + f"?view=decisions&action_id={action['action_id']}").json()["items"]
    assert {item["id"]: item["assessment_generation"] for item in decisions} == {
        first["id"]: 1, alias["id"]: 1, second["id"]: 2,
    }
    receipt = consume_body(second)
    assert consume(system, second, receipt)["granted"]
    publish(system, version="3")
    replay = consume(system, second, receipt, expected=200)
    assert replay["replayed"] and not replay["granted"]
    assert consume(system, first, expected=409)["error"]["code"] == "action_already_consumed"
    assert check(system, {**value, "request_id": new_id()}, expected=409)["error"]["code"] == "action_already_consumed"


def test_context_changes_revoke_old_approval_and_owner_rejection_remains_terminal(system):
    approval_settings(system, context_enabled=True, context_required=True)
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    policy(system, "ask")
    value = request(system, registration)
    first = check(system, value)
    decide(system, first["approval"]["id"])
    publish(system, version="2")
    assert consume(system, first, expected=409)["error"]["code"] == "context_changed"
    second = check(system, {**value, "request_id": new_id()})
    assert second["approval"]["id"] != first["approval"]["id"]
    assert second["approval"]["assessment_generation"] == 2
    old = browser(system, "GET", "me/approvals/" + first["approval"]["id"], user="owner").json()
    assert old["reason_code"] == "context_changed"
    assert old["assessment"]["knowledge"] == first["assessment"]["knowledge"]
    decide(system, second["approval"]["id"], "reject")
    publish(system, version="3")
    assert check(system, {**value, "request_id": new_id()}, expected=409)["error"]["code"] == "action_rejected"
    assert len(system.provider.requests) == 2


def test_scope_rebinding_requires_a_new_assessment(system):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    value = request(system, registration)
    first = check(system, value)
    assert bind(system, registration, "account:other").status_code == 200
    assert consume(system, first, expected=409)["error"]["code"] == "context_changed"
    second = check(system, {**value, "request_id": new_id()})
    assert second["decision"]["action"] == "block"
    assert all("production" not in doc["text"] for doc in second["assessment"]["knowledge"]["documents"])


def test_source_publication_serializes_with_first_release(system):
    approval_settings(system, context_enabled=True, context_required=True)
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    first = check(system, request(system, registration))
    with ThreadPoolExecutor(max_workers=1) as pool:
        with system.db.transaction() as conn:
            system.db.execute("SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR UPDATE",
                              system.tenant["id"], conn=conn)
            pid = system.db.scalar("SELECT pg_backend_pid()", conn=conn)
            pending = pool.submit(consume, system, first, expected=409)
            wait_for_blocker(system.db, pid)
            system.db.execute("UPDATE tenant_knowledge SET revision=revision+1 WHERE tenant_id=$1",
                              system.tenant["id"], conn=conn)
        assert pending.result(timeout=3)["error"]["code"] == "context_changed"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0


def test_late_provider_completion_cannot_overwrite_a_new_assessment_generation(system):
    approval_settings(system, context_enabled=True, context_required=True)
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    value = request(system, registration)
    system.provider.block()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(check, system, value)
        assert system.provider.entered.wait(3)
        system.db.execute("UPDATE inline_guardrail_events SET deadline_at=clock_timestamp()-interval '1 second'")
        expired = check(system, value)
        assert expired["assessment"]["reason"] == "timeout"
        publish(system, version="2", production=False)
        system.provider.entered.clear()
        second = pool.submit(check, system, {**value, "request_id": new_id()})
        assert system.provider.entered.wait(3)
        alias_value = {**value, "request_id": new_id()}
        alias = check(system, alias_value, expected=202)
        assert alias["assessment_generation"] == 2
        system.provider.release()
        assert first.result(timeout=3)["assessment"] == expired["assessment"]
        renewed = second.result(timeout=3)
    assert renewed["assessment_generation"] == 2
    assert renewed["assessment"]["status"] == "scored"
    assert check(system, alias_value)["assessment"] == renewed["assessment"]
    assert "development" in json.dumps(renewed["assessment"]["knowledge"])
    assert system.db.many("SELECT generation,status FROM inline_guardrail_assessments ORDER BY generation") == [
        {"generation": 1, "status": "unavailable"}, {"generation": 2, "status": "scored"},
    ]
    assert len(system.provider.requests) == 2


def test_source_expiry_prevents_release_and_requires_reassessment(system):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    system.db.execute("UPDATE knowledge_sources SET fresh_until=clock_timestamp()+interval '1 second'")
    value = request(system, registration)
    first = check(system, value)
    assert first["assessment"]["knowledge"]["status"] == "matched"
    system.db.execute(
        "SELECT pg_sleep(GREATEST(0,extract(epoch FROM $1::timestamptz-clock_timestamp()))+0.001)",
        first["assessment"]["knowledge"]["valid_until"],
    )
    assert consume(system, first, expected=409)["error"]["code"] == "context_changed"
    second = check(system, {**value, "request_id": new_id()})
    assert second["assessment_generation"] == 2
    assert second["decision"]["action"] == "block"
    assert second["assessment"]["knowledge"]["documents"] == []


def test_enrichment_lock_timeout_never_dispatches_unpinned_context(system):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    with system.db.transaction() as conn:
        system.db.execute("SELECT revision FROM tenant_knowledge WHERE tenant_id=$1 FOR UPDATE",
                          system.tenant["id"], conn=conn)
        started = time.monotonic()
        value = request(system, registration)
        check(system, value, expected=503)
        assert time.monotonic() - started < 0.5
    assert system.provider.requests == []
    system.db.execute("UPDATE inline_guardrail_events SET deadline_at=clock_timestamp()-interval '1 second'")
    expired = check(system, value)
    assert expired["decision"]["action"] == "block"
    assert consume(system, expired, expected=409)["error"]["code"] == "context_changed"
    renewed = check(system, {**value, "request_id": new_id()})
    assert renewed["assessment_generation"] == 2
    assert renewed["assessment"]["knowledge"]["status"] == "matched"
    assert len(system.provider.requests) == 1


@pytest.mark.parametrize("changes,expected_calls,executes", [(1, 2, True), (5, 3, False)])
def test_managed_client_reassesses_with_same_action_and_bounded_retries(system, tmp_path, changes, expected_calls, executes):
    approval_settings(system, context_enabled=True, context_required=True)
    publish(system)
    registration = registered(system)
    assert bind(system, registration).status_code == 200

    class UpdatingTransport(ReceiverTransport):
        count = 0

        async def handle_async_request(self, outgoing):
            if outgoing.url.path.endswith("/consume") and self.count < changes:
                self.count += 1
                publish(system, version=str(self.count + 1))
            return await super().handle_async_request(outgoing)

    async def scenario():
        callback = Callback()
        transport = UpdatingTransport(system)
        value = held(registration, nonce="omg drain us-west-1")
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, journal, _):
            result = await gate.gate(value, callback)
            assert (result.status == "succeeded") == executes, result
            assert len(callback.raw) == int(executes)
            assert journal.action(value.logical_id)["consume_uncertain"] == 0
        requests = [row["request"] for row in transport.completed if row["path"].endswith("guardrail-checks")]
        assert len({row["request_id"] for row in requests}) == expected_calls
        assert len({row["action_commitment"] for row in requests}) == 1
        assert len({row["target"]["evidence"]["logical_id"] for row in requests}) == 1
        assert len(system.provider.requests) == expected_calls
        assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == int(executes)

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["check", "status", "consume", "provider"])
def test_known_required_context_prevents_outage_execution(system, tmp_path, failure):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
    publish(system)
    registration = registered(system)
    assert bind(system, registration).status_code == 200

    class OutageTransport(ReceiverTransport):
        fail = None

        async def handle_async_request(self, outgoing):
            suffix = {"check": "guardrail-checks", "status": "/status", "consume": "/consume"}.get(self.fail)
            if suffix and outgoing.url.path.endswith(suffix):
                raise httpx.ConnectError("receiver unavailable", request=outgoing)
            return await super().handle_async_request(outgoing)

    async def scenario():
        callback = Callback()
        transport = OutageTransport(system)
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, journal, _):
            # Learn the authenticated requirement before simulating a later
            # status outage. Check/consume failures also occur on the first action.
            if failure == "status":
                await gate._status()
            if failure == "provider":
                system.provider.status = 500
            else:
                transport.fail = failure
            result = await gate.gate(held(registration, nonce="omg drain us-west-1"), callback)
            assert result.status in ("blocked", "uncertain"), result
            assert callback.raw == []
            assert journal.context_policy()["required"] is True
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0

    asyncio.run(scenario())


def test_new_client_keeps_legacy_protocol_and_rejects_known_policy_downgrade(system, tmp_path):
    approval_settings(system)
    registration = registered(system)

    class LegacyTransport(ReceiverTransport):
        legacy = True

        async def handle_async_request(self, outgoing):
            if self.legacy and outgoing.url.path.endswith("guardrail-checks"):
                assert "context_version" not in json.loads(await outgoing.aread())
            response = await super().handle_async_request(outgoing)
            if self.legacy and outgoing.url.path.endswith("/status"):
                value = json.loads(response.content)
                value.pop("context_version", None)
                value.pop("context_policy", None)
                return httpx.Response(response.status_code, json=value)
            return response

    async def scenario():
        callback = Callback()
        transport = LegacyTransport(system)
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, journal, _):
            assert (await gate.gate(held(registration), callback)).status == "succeeded"
            transport.legacy = False
            approval_settings(system, context_enabled=True, context_required=True, context_failure_action="block")
            await gate._status()
            assert journal.context_policy()["required"] is True
            transport.legacy = True
            result = await gate.gate(held(registration), callback)
            assert result.status == "blocked" and result.reason == "policy_changed"
            assert len(callback.raw) == 1
            assert journal.context_policy()["required"] is True

    asyncio.run(scenario())


@pytest.mark.parametrize("failure_action,static,expected", [("ask", None, "ask"), ("block", None, "block"), ("ask", "deny", "block")])
def test_required_context_provider_failure_keeps_configured_and_static_floors(system, failure_action, static, expected):
    approval_settings(system, context_enabled=True, context_required=True, context_failure_action=failure_action)
    publish(system)
    registration = managed(system)
    assert bind(system, registration).status_code == 200
    policy(system, static)
    system.provider.status = 500
    result = check(system, request(system, registration))
    assert result["assessment"]["status"] == "unavailable"
    assert result["assessment"]["knowledge"]["status"] == "matched"
    assert result["decision"]["action"] == expected
    if expected == "ask":
        assert consume(system, result, expected=409)["error"]["code"] == "approval_pending"
        decide(system, result["approval"]["id"])
        assert consume(system, result)["granted"]
    else:
        assert consume(system, result, expected=409)["error"]["code"] == "action_blocked"
