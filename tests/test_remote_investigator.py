"""Real pinned native execution through HTTP, SQLite and tenant PostgreSQL fences."""

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from functools import partial
import json
import subprocess
import sys
import threading
import time

import httpx
import pytest

from openaidr_api.app import Config as APIConfig, create_app
from openaidr_api.investigations.worker import Worker, runtime
from openaidr_api.threat_intel import keys
from openaidr_api_client.contracts import investigations as wire
from openaidr.server import session_investigator as inv
from openaidr_api_client.client import Connection, Unavailable
from openaidr.server.remote_investigator import Recovery, RemoteRuntime
from test_codex_investigator import NativeProvider, runtime_config
from test_inline_guardrail import system as system
from test_session_investigator import (
    attempt, measured, no_finding, proposal, remote_exchange, remote_operation, remote_reply,
)
from test_store import db as db
from intelligence_service_fixtures import ContractClient


class LostAcknowledgement(httpx.AsyncBaseTransport):
    def __init__(self, app, kinds, protocol_version=1):
        self.inner = httpx.ASGITransport(app=app)
        self.kinds, self.dropped = set(kinds), []
        self.protocol_version, self.paths, self.steps = protocol_version, [], []

    async def handle_async_request(self, request):
        self.paths.append(request.url.path)
        if self.protocol_version == 2 and request.url.path.startswith("/v1/investigations"):
            return httpx.Response(404, json={"detail": "Not Found"})
        if request.method == "POST" and request.url.path.endswith("/exchange"):
            message = json.loads(request.content)
            if message.get("type") == "step":
                self.steps.append(message)
        response = await self.inner.handle_async_request(request)
        if request.method == "POST" and request.url.path.endswith("/exchange"):
            kind = json.loads(request.content).get("type")
            if kind in self.kinds:
                self.kinds.remove(kind)
                self.dropped.append(kind)
                await response.aclose()
                raise httpx.ReadError("synthetic lost acknowledgement", request=request)
        return response


@contextmanager
def service(system, tmp_path, provider, *, lost=(), protocol_version=1):
    cfg = runtime_config(system)
    key_db = tmp_path / "keys.sqlite3"
    keys.initialize(key_db)
    credential = tmp_path / "tenant.key"
    keys.issue(key_db, system.tenant["id"], credential)
    connection = Connection("https://intelligence.test", credential.read_text().strip(),
                            system.tenant["id"])
    config = APIConfig(str(key_db), openai_key="synthetic-service-only-key",
                       guardrail_key="synthetic-guardrail-key" if hasattr(provider, "scored") else "",
                       investigation_db=str(tmp_path / "jobs.sqlite3"),
                       investigation_binary=cfg.session_investigator_binary)
    app = create_app(config, version="2026.10.27+1234567", transport=httpx.MockTransport(provider.handle))
    transport = LostAcknowledgement(app, lost, protocol_version)
    native = []

    def factory():
        execution = runtime(config, provider_transport=httpx.MockTransport(provider.handle))
        native.append(execution)
        return execution

    stop = threading.Event()
    with ContractClient(app):
        worker = Worker(app.state.investigations, factory, poll_seconds=0.02)
        thread = threading.Thread(target=worker.run, args=(stop,))
        thread.start()
        try:
            yield app.state.investigations, connection, transport, native, stop
        finally:
            stop.set()
            thread.join(10)
            assert not thread.is_alive()
    assert all(execution._process is None for execution in native)


def outcome_diagnostics(system, claim, result):
    """Keep synthetic failure reports useful when a bounded mailbox is unavailable."""
    return json.dumps({
        "result": result,
        "attempt": system.db.one(
            "SELECT state,result FROM session_investigation_attempts WHERE id=$1", claim["attempt_id"],
        ),
        "usage": system.db.many(
            "SELECT status,input_tokens,output_tokens,cost_usd FROM model_usage WHERE investigation_attempt_id=$1",
            claim["attempt_id"],
        ),
    }, default=str, sort_keys=True)


def execute(system, claim, connection, transport):
    async def run():
        worker = inv.Investigator(system.db, lambda: RemoteRuntime(system.db, connection, transport=transport))
        try:
            return await worker.run_claim(claim)
        finally:
            await worker.aclose()
    return asyncio.run(run())


@pytest.mark.parametrize("mode", ["read", "incident", "token-budget", "missing-cache-write"])
def test_selected_service_owns_counts_native_dispatch_and_settled_reports(system, tmp_path, mode):
    protocol_version = 1
    value = attempt(system, **({"max_tokens_per_attempt": 500} if mode == "token-budget" else {}))
    provider = NativeProvider(system, value, mode, tmp_path / "forbidden")
    with service(system, tmp_path, provider, lost=("step", "reply", "step_ack", "finish"),
                 protocol_version=protocol_version) as (_, connection, transport, _, _):
        result = execute(system, value.claim, connection, transport)
    binding = system.db.one("SELECT * FROM session_investigation_remote_bindings WHERE attempt_id=$1",
                            value.claim["attempt_id"])
    assert binding["create_request"]["protocol_version"] == binding["profile"]["protocol_version"] == protocol_version
    assert transport.paths[0] == "/v1/investigations/runtime"
    assert transport.steps and all("context" in step for step in transport.steps)
    assert all("prompt" not in step for step in transport.steps)
    assert provider.counted
    if mode == "token-budget":
        assert not provider.inferred and result["report_status"] == "inconclusive"
    else:
        assert provider.inferred
        assert result["report_status"] == {"read": "no_finding", "incident": "finding",
                                           "missing-cache-write": "inconclusive"}[mode], outcome_diagnostics(system, value.claim, result)
    usage = system.db.many("SELECT * FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"])
    assert len(usage) == len(provider.inferred)
    if mode == "missing-cache-write":
        assert usage[0]["cost_usd"] is None and usage[0]["cache_write_input_tokens"] is None
    if mode in ("read", "incident"):
        assert set(transport.dropped) == {"step", "reply", "step_ack", "finish"}
        messages = system.db.many("SELECT * FROM session_investigation_remote_messages WHERE attempt_id=$1",
                                  value.claim["attempt_id"])
        assert all(message["ack_revision"] for message in messages)
        if mode == "read":
            assert any(message["operation_kind"] == "read_tool" and message["read_id"] for message in messages)


@pytest.mark.parametrize("phase", ["before_settlement", "after_settlement", "before_result_ack"])
def test_worker_loss_never_repeats_a_paid_call_or_publishes_output(system, tmp_path, monkeypatch, phase):
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    with service(system, tmp_path, provider) as (store, connection, transport, _, _):
        method = {"before_settlement": "operation", "after_settlement": "take_reply",
                  "before_result_ack": "complete_step"}[phase]
        original = getattr(store, method)
        failed = []

        def crash(*args):
            result = original(*args)
            target = (phase == "before_result_ack" or phase == "before_settlement" and args[-2] == "finish_call"
                      or phase == "after_settlement" and isinstance(result, dict) and result.get("value") is True)
            if target and not failed:
                failed.append(True)
                raise RuntimeError("synthetic worker loss")
            return result

        monkeypatch.setattr(store, method, crash)
        result = execute(system, value.claim, connection, transport)
        binding = system.db.one("SELECT * FROM session_investigation_remote_bindings WHERE attempt_id=$1",
                                value.claim["attempt_id"])
        assert store.status(connection.tenant_id, binding["remote_id"], protocol_version=binding["profile"]["protocol_version"])["state"] in wire.TERMINAL
        assert store.claim("replacement", wire.digest(binding["profile"])) is None
    assert failed and len(provider.inferred) == 1
    assert result["report_status"] == "inconclusive"
    assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0
    usage = system.db.one("SELECT * FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"])
    assert usage["input_tokens"] == 1000 and usage["output_tokens"] == 20


def test_wrong_tenant_binding_fails_before_create_or_token_count(system, tmp_path):
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    with service(system, tmp_path, provider) as (_, connection, transport, _, _):
        result = execute(system, value.claim, replace(connection, tenant_id="00000000-0000-0000-0000-000000000001"), transport)
    assert result["report_status"] == "inconclusive" and not provider.counted
    assert system.db.scalar("SELECT count(*) FROM session_investigation_remote_bindings") == 0


@pytest.mark.parametrize("reason", ["revoked", "expired"])
def test_authority_change_after_count_prevents_inference(system, tmp_path, reason):
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    original = provider.handle

    def handle(request):
        response = original(request)
        if request.url.path.endswith("/input_tokens"):
            if reason == "expired":
                system.db.execute("UPDATE session_investigation_attempts SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                                  value.claim["attempt_id"])
            else:
                system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["sensor"][0]["id"])
        return response

    provider.handle = handle
    with service(system, tmp_path, provider) as (_, connection, transport, _, _):
        result = execute(system, value.claim, connection, transport)
    assert provider.counted and not provider.inferred
    assert result["report_status"] == "inconclusive"


@pytest.mark.parametrize("failure", ["connection", "not_found"])
def test_tenant_restart_reconciles_retained_late_usage_without_reexecution(
        system, tmp_path, monkeypatch, failure):
    protocol_version = 1
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    original = RemoteRuntime._exchange

    def interrupted(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if result["pending"] and result["pending"]["kind"] == "finish_call":
            if failure == "not_found":
                raise Unavailable("synthetic missing endpoint after dispatch", status_code=404)
            raise RuntimeError("synthetic tenant connection loss")
        return result

    with service(system, tmp_path, provider, protocol_version=protocol_version) as (_, connection, transport, _, _):
        with monkeypatch.context() as patch:
            patch.setattr(RemoteRuntime, "_exchange", interrupted)
            result = execute(system, value.claim, connection, transport)
        assert result["report_status"] == "inconclusive"
        assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) is None
        # Recovery must keep the stored protocol and never negotiate, start a
        # step, or repeat paid work.
        transport.paths.clear()
        recovery = Recovery(system.db, connection, transport=transport)
        assert recovery.tick()
        assert not recovery.tick()
        assert transport.paths and all(path.startswith(f"/v{protocol_version}/investigations/")
                                       and not path.endswith("/runtime") for path in transport.paths)
        assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) > 0
        assert system.db.scalar("SELECT count(*) FROM findings WHERE investigation_job_id=$1", value.claim["job_id"]) == 0
    assert len(provider.inferred) == 1


def test_worker_shutdown_keeps_measured_usage_and_withholds_publication(system, tmp_path):
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    original = provider.handle
    with service(system, tmp_path, provider) as (_, connection, transport, _, stop):
        def handle(request):
            response = original(request)
            if request.url.path == "/v1/responses":
                stop.set()
            return response
        provider.handle = handle
        result = execute(system, value.claim, connection, transport)
    assert len(provider.inferred) == 1 and result["report_status"] == "inconclusive"
    usage = system.db.one("SELECT * FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"])
    assert usage["input_tokens"] == 1000 and usage["output_tokens"] == 20


def test_tenant_runtime_import_does_not_load_native_execution():
    result = subprocess.run([sys.executable, "-c", """
import importlib.abc
import sys

class WithoutNative(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"api", "openaidr_api"}:
            raise AssertionError("Tenant imported native execution: " + fullname)

sys.meta_path.insert(0, WithoutNative())
from openaidr_api_client.contracts import investigations
from openaidr.server.remote_investigator import RemoteRuntime
from openaidr.server import app, skill_worker
from openaidr.server.guardrail import clients
from openaidr.sensor import cli
assert investigations.MAX_FRAME == 8 << 20
assert RemoteRuntime.remote
from openaidr_api_client.contracts import investigation_runtime
from openaidr.server import session_investigator
for module in (investigation_runtime, session_investigator):
    assert not any(hasattr(module, name) for name in ("GUIDANCE", "TOOLS", "OUTPUT_SCHEMA"))
"""], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("change", [None, "platform", "executable_sha256", "version", "model"])
def test_remote_readiness_accepts_only_supported_runtime_profiles(change):
    metadata = dict(protocol_version=1, version=wire.native.VERSION, platform="Linux/x86_64",
                    executable_sha256=wire.native.EXECUTABLE_DIGESTS[("Linux", "x86_64")])
    profile = wire.profile(metadata)
    if change:
        profile[change] = "0" * 64 if change == "executable_sha256" else "unsupported"
    response = dict(ready=True, reason="", supported_models=[wire.native.MODEL],
                    profile=profile, runtime_profile_sha256=wire.digest(profile),
                    limits={}, build="fixture")
    connection = Connection("https://intelligence.test", "oati_" + "a" * 32 + "." + "b" * 43,
                            "019a0000-0000-7000-8000-000000000001")
    runtime = RemoteRuntime(None, connection,
                            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=response)))
    try:
        readiness = runtime.ready()
        assert readiness["ready"] is (change is None)
        if change is None:
            assert {key: readiness[key] for key in profile} == profile
        else:
            assert readiness["reason"] == "runtime_unavailable"
    finally:
        runtime.close()


@pytest.mark.parametrize("response_kind", [404, 401, 403, 500, 503, "timeout", "invalid", "not_ready"])
def test_runtime_requires_v1_before_binding_without_protocol_fallback(response_kind):
    metadata = dict(protocol_version=1, version=wire.native.VERSION, platform="Linux/x86_64",
                    executable_sha256=wire.native.EXECUTABLE_DIGESTS[("Linux", "x86_64")])
    profile = wire.profile(metadata)
    ready = dict(ready=True, reason="", supported_models=[wire.native.MODEL], profile=profile,
                 runtime_profile_sha256=wire.digest(profile), limits={}, build="fixture")
    paths = []

    def handle(request):
        paths.append(request.url.path)
        assert request.url.path == "/v1/investigations/runtime"
        if response_kind == "timeout":
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        if response_kind == "invalid":
            return httpx.Response(200, json={**ready, "profile": {**profile, "protocol_version": 2}})
        if response_kind == "not_ready":
            return httpx.Response(200, json={**ready, "ready": False, "profile": None,
                                            "runtime_profile_sha256": None})
        return httpx.Response(response_kind, json={"detail": "unavailable"})

    connection = Connection("https://intelligence.test", "oati_" + "a" * 32 + "." + "b" * 43,
                            "019a0000-0000-7000-8000-000000000001")
    runtime = RemoteRuntime(None, connection, transport=httpx.MockTransport(handle))
    try:
        assert runtime.ready() == dict(ready=False, reason="runtime_unavailable", supported_models=[])
        assert paths == ["/v1/investigations/runtime"]
        assert runtime.job is None and runtime.bridge is None and runtime.profile is None
    finally:
        runtime.close()


@contextmanager
def retained_investigation(system, tmp_path):
    """A stopped tenant's structured v1 records, with real HTTP/SQLite and no worker."""
    key_db, credential = tmp_path / "keys.sqlite3", tmp_path / "tenant.key"
    keys.initialize(key_db)
    keys.issue(key_db, system.tenant["id"], credential)
    connection = Connection("https://intelligence.test", credential.read_text().strip(), system.tenant["id"])
    app = create_app(APIConfig(str(key_db), investigation_db=str(tmp_path / "jobs.sqlite3")), version="fixture")
    with ContractClient(app):
        remote = remote_exchange(system, tmp_path, protocol_version=1, connection=connection)
        transport = LostAcknowledgement(app, (), protocol_version=1)
        yield remote, transport


def forbid_continuation(monkeypatch):
    from openaidr.server.investigation_bridge import Bridge

    def forbidden(*args, **kwargs):
        pytest.fail("Retained recovery attempted new work or republished output")

    for name in ("ready", "bind_attempt", "run"):
        monkeypatch.setattr(RemoteRuntime, name, forbidden)
    monkeypatch.setattr(Bridge, "step_message", forbidden)
    for name in ("next_step", "read_tool", "admit_call", "complete_step", "publish_report"):
        monkeypatch.setattr(inv, name, forbidden)


@pytest.mark.parametrize("delivery", ["unsettled", "lost_request", "lost_ack"])
def test_retained_v1_late_usage_settles_once_without_prompt_or_admission(system, tmp_path, monkeypatch, delivery):
    with retained_investigation(system, tmp_path) as (remote, transport):
        counted = proposal(remote.step)
        assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
        operation = remote_operation(remote, "finish_call", measured(counted["request_id"]))
        if delivery != "unsettled":
            message = remote.bridge.reply(operation, **remote.callbacks)
            if delivery == "lost_ack":
                remote.exchange(remote.connection.tenant_id, remote.job, message)
            else:
                handle = transport.handle_async_request

                async def terminal_before_receipt(request):
                    if request.url.path.endswith("/exchange") and json.loads(request.content).get("type") == "reply":
                        assert remote.status(remote.connection.tenant_id, remote.job)["state"] in wire.TERMINAL
                        assert json.loads(request.content) == message
                    return await handle(request)

                monkeypatch.setattr(transport, "handle_async_request", terminal_before_receipt)
        inv.stop_attempt(system.db, remote.value.claim, "runtime_unavailable")
        forbid_continuation(monkeypatch)
        recovery = Recovery(system.db, remote.connection, transport=transport)
        assert recovery.tick()
        assert not recovery.tick()
        assert not recovery.tick()
        usage = system.db.one("SELECT * FROM model_usage WHERE investigation_request_id=$1", counted["request_id"])
        assert usage["input_tokens"] == 1000 and usage["output_tokens"] == 20 and usage["cost_usd"] > 0
        assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", remote.value.claim["attempt_id"]) == 1
        assert system.db.scalar("SELECT count(*) FROM findings") == 0
        assert all(path.startswith("/v1/investigations/") and not path.endswith("/runtime")
                   for path in transport.paths)
        assert not transport.steps
        assert remote.status(remote.connection.tenant_id, remote.job)["state"] == "cancelled"
        if delivery == "lost_request":
            from openaidr_api.investigations.store import MailboxError
            assert remote.store.take_reply(remote.connection.tenant_id, remote.job, remote.generation,
                                           operation["operation_id"])["value"] is True
            # A draining old worker can consume the historical receipt, but it
            # cannot continue reads, ask for another permit, or publish a step.
            for kind, payload in (("admit_call", counted), ("read_tool", dict(
                    call_id="blocked", name="search_sessions", arguments={}))):
                with pytest.raises(MailboxError, match="job_stopped"):
                    remote_operation(remote, kind, payload)
            with pytest.raises(MailboxError, match="job_stopped"):
                remote.store.complete_step(remote.connection.tenant_id, remote.job, remote.generation, json.dumps(no_finding()))
            stored = system.db.one("SELECT * FROM session_investigation_remote_messages WHERE id=$1", message["message_id"])
            assert stored["message"] == message and stored["message_sha256"] == wire.digest(message)
            assert stored["ack_revision"] is not None


@pytest.mark.parametrize("state", ["read_tool", "admit_call", "dispatched", "result", "waiting_step"])
def test_retained_v1_unfinished_work_cancels_without_replay_or_publication(system, tmp_path, monkeypatch, state):
    with retained_investigation(system, tmp_path) as (remote, transport):
        counted = proposal(remote.step)
        if state == "read_tool":
            remote_operation(remote, "read_tool", dict(call_id="retained-read", name="search_sessions", arguments={}))
        elif state == "admit_call":
            remote_operation(remote, "admit_call", counted)
        else:
            assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
            if state != "dispatched":
                assert remote_reply(remote, remote_operation(remote, "finish_call", measured(counted["request_id"])))["value"]
                remote.store.complete_step(remote.connection.tenant_id, remote.job, remote.generation, json.dumps(no_finding()))
            if state == "waiting_step":
                result = remote.exchange(remote.connection.tenant_id, remote.job, dict(type="poll", ack_for=None))["step_result"]
                message = remote.bridge.accept_step(remote.step["id"], result,
                    partial(inv.complete_step, system.db, remote.value.claim, remote.step["id"]))
                delivered = remote.exchange(remote.connection.tenant_id, remote.job, message)
                remote.bridge.acknowledge(message, delivered["ack"])
        # The final process sees an expired attempt after the old worker drained.
        system.db.execute("UPDATE session_investigation_attempts SET deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1",
                          remote.value.claim["attempt_id"])
        forbid_continuation(monkeypatch)
        before = system.db.many("SELECT id,request_sha256,reserved_tokens FROM session_investigation_requests")
        assert Recovery(system.db, remote.connection, transport=transport).tick()
        assert system.db.many("SELECT id,request_sha256,reserved_tokens FROM session_investigation_requests") == before
        if state == "dispatched":
            assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_attempt_id=$1", remote.value.claim["attempt_id"]) is None
            assert before[0]["reserved_tokens"] > 0
        assert system.db.scalar("SELECT count(*) FROM session_investigation_reads") == 0
        assert system.db.scalar("SELECT count(*) FROM findings") == 0
        assert remote.status(remote.connection.tenant_id, remote.job)["state"] == "cancelled"
        assert not transport.steps


def test_retained_v1_publication_finishes_from_original_receipt_without_republishing(system, tmp_path, monkeypatch):
    with retained_investigation(system, tmp_path) as (remote, transport):
        counted = proposal(remote.step)
        assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
        assert remote_reply(remote, remote_operation(remote, "finish_call", measured(counted["request_id"])))["value"]
        remote.store.complete_step(remote.connection.tenant_id, remote.job, remote.generation, json.dumps(no_finding()))
        result = remote.exchange(remote.connection.tenant_id, remote.job, dict(type="poll", ack_for=None))["step_result"]
        ack = remote.bridge.accept_step(remote.step["id"], result,
            partial(inv.complete_step, system.db, remote.value.claim, remote.step["id"]))
        delivered = remote.exchange(remote.connection.tenant_id, remote.job, ack)
        remote.bridge.acknowledge(ack, delivered["ack"])
        published, finish = remote.bridge.finish(partial(inv.publish_report, system.db, remote.value.claim))
        assert published["report_status"] == "no_finding"
        # The finish body committed with publication, but its HTTP request was lost.
        forbid_continuation(monkeypatch)
        recovery = Recovery(system.db, remote.connection, transport=transport)
        assert recovery.tick() and not recovery.tick() and not recovery.tick()
        assert remote.status(remote.connection.tenant_id, remote.job)["state"] == "completed"
        assert remote.bridge.recovery()["publication"] == published
        assert remote.bridge.recovery()["messages"] == []
        assert transport.paths == [f"/v1/investigations/{remote.job}/exchange"]
        assert not transport.steps and finish["type"] == "finish"


def test_old_receiver_is_unavailable_before_binding_or_provider_work(system, tmp_path):
    value = attempt(system)
    provider = NativeProvider(system, value, "incident", tmp_path / "forbidden")
    with service(system, tmp_path, provider, protocol_version=2) as (_, connection, transport, _, _):
        result = execute(system, value.claim, connection, transport)
    assert result["report_status"] == "inconclusive"
    assert transport.paths == ["/v1/investigations/runtime"]
    assert not provider.counted and not provider.inferred
    assert system.db.scalar("SELECT count(*) FROM session_investigation_remote_bindings") == 0
    assert system.db.scalar("SELECT count(*) FROM model_usage WHERE investigation_attempt_id=$1", value.claim["attempt_id"]) == 0


@pytest.mark.parametrize("failure", ["unavailable", "active", "foreign"])
def test_retained_receipt_never_replays_without_confirmed_original_job_cancellation(system, tmp_path, monkeypatch, failure):
    with retained_investigation(system, tmp_path) as (remote, transport):
        counted = proposal(remote.step)
        assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
        operation = remote_operation(remote, "finish_call", measured(counted["request_id"]))
        message = remote.bridge.reply(operation, **remote.callbacks)
        inv.stop_attempt(system.db, remote.value.claim, "runtime_unavailable")
        handle = transport.handle_async_request
        replies = []

        async def cancellation_failure(request):
            if request.url.path.endswith("/cancel"):
                if failure == "unavailable":
                    return httpx.Response(503, json={"error": "unavailable"})
                current = remote.exchange(remote.connection.tenant_id, remote.job, dict(type="poll", ack_for=None))
                if failure == "foreign":
                    current = {**current, "id": "019a0000-0000-7000-8000-000000000001", "state": "cancelled"}
                return httpx.Response(200, json=current)
            if request.url.path.endswith("/exchange") and json.loads(request.content).get("type") == "reply":
                replies.append(json.loads(request.content))
            return await handle(request)

        monkeypatch.setattr(transport, "handle_async_request", cancellation_failure)
        forbid_continuation(monkeypatch)
        with pytest.raises((Unavailable, inv.InvestigationStopped)):
            Recovery(system.db, remote.connection, transport=transport).tick()
        assert replies == [] and not transport.steps
        stored = system.db.one("SELECT * FROM session_investigation_remote_messages WHERE id=$1", message["message_id"])
        assert stored["message"] == message and stored["message_sha256"] == wire.digest(message)
        assert stored["ack_revision"] is None
        assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_request_id=$1", counted["request_id"]) > 0


def test_reset_preserves_retained_v2_binding_without_sending_requests(system, tmp_path):
    with retained_investigation(system, tmp_path) as (remote, transport):
        counted = proposal(remote.step)
        assert remote_reply(remote, remote_operation(remote, "admit_call", counted))["ok"]
        inv.stop_attempt(system.db, remote.value.claim, "runtime_unavailable")
        system.db.execute("""UPDATE session_investigation_remote_bindings
            SET profile=profile || '{"protocol_version":2}'::jsonb,
                create_request=create_request || '{"protocol_version":2}'::jsonb
            WHERE attempt_id=$1""", remote.value.claim["attempt_id"])
        before = system.db.one("SELECT * FROM session_investigation_remote_bindings WHERE attempt_id=$1",
                               remote.value.claim["attempt_id"])
        with pytest.raises(ValueError):
            Recovery(system.db, remote.connection, transport=transport).tick()
        assert not transport.paths
        assert system.db.one("SELECT * FROM session_investigation_remote_bindings WHERE attempt_id=$1",
                             remote.value.claim["attempt_id"]) == before
        assert system.db.scalar("SELECT cost_usd FROM model_usage WHERE investigation_request_id=$1",
                                counted["request_id"]) is None
