"""Managed journal and gate through real receiver HTTP and PostgreSQL.

Only the external JEV transport and receiver connection failures are simulated.
Native execution is represented by an async release callback.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from copy import deepcopy
import hashlib
import json
import ssl

import httpx
import pytest

from openaidr.guardrail.backend import Backend, BackendRejected
from openaidr.guardrail.gate import Gate, HeldBoundary, JournalDelivery, NativeOutcome
from openaidr.guardrail.journal import Journal, JournalError
from openaidr.core.event import new_id
from openaidr.core.protocol import default_sensor_config
from openaidr.core.policy import Policy
from openaidr.sensor.tls import client_options
from test_approvals import approval_settings, consume, decide, sensor_post
from test_inline_guardrail import Provider, browser, check, event, payload, system as system
from test_session_aggregation import BOUNDARIES, detection_settings, finalized, registered, snapshot_page
from test_session_ownership import wait_for_blocker
from test_store import db as db


class BrokenBody(httpx.AsyncByteStream):
    def __init__(self, request):
        self.request = request

    async def __aiter__(self):
        yield b"{"
        raise httpx.ReadTimeout("fixture response body timeout", request=self.request)


class ReceiverTransport(httpx.AsyncBaseTransport):
    def __init__(self, system):
        self.system = system
        self.offline = False
        self.drop_once = None
        self.broken_body_statuses = set()
        self.certificate_error = False
        self.completed = []
        self.changed = asyncio.Condition()

    async def handle_async_request(self, request):
        if self.certificate_error:
            raise httpx.ConnectError("fixture TLS authentication failure", request=request) from ssl.SSLCertVerificationError(
                1, "fixture certificate verification failed",
            )
        if self.offline:
            raise httpx.ConnectError("fixture receiver outage", request=request)
        content = await request.aread()
        response = await asyncio.to_thread(
            self.system.client.request, request.method, request.url.raw_path.decode(),
            content=content, headers=dict(request.headers),
        )
        entry = {"path": request.url.path, "request": json.loads(content),
                 "status": response.status_code, "response": response.json()}
        async with self.changed:
            self.completed.append(entry)
            self.changed.notify_all()
        if self.drop_once and request.url.path.endswith(self.drop_once):
            self.drop_once = None
            raise httpx.ReadTimeout("fixture lost committed response", request=request)
        headers = {key: value for key, value in response.headers.items()
                   if key.lower() not in ("content-encoding", "content-length", "transfer-encoding")}
        if response.status_code in self.broken_body_statuses:
            return httpx.Response(response.status_code, stream=BrokenBody(request), headers=headers)
        return httpx.Response(response.status_code, content=response.content, headers=headers)

    async def wait_for(self, suffix, *, after=0):
        async with self.changed:
            await asyncio.wait_for(self.changed.wait_for(
                lambda: any(item["path"].endswith(suffix) for item in self.completed[after:])
            ), timeout=5)
        return next(item for item in self.completed[after:] if item["path"].endswith(suffix))


def enrollment(system, device="sensor"):
    sensor, token, _ = system.sensors[device]
    return {"server_url": "http://127.0.0.1", "tenant_id": sensor["tenant_id"],
            "sensor_id": sensor["id"], "sensor_token": token}


def binding(system, registration):
    return {**{key: value for key, value in enrollment(system).items() if key != "sensor_token"},
            "product": registration["product"], "session_id": registration["external_id"],
            "registration_id": registration["id"], "epoch_id": registration["delivery_epoch"]}


@asynccontextmanager
async def foundation(system, path, registration, *, capture=None, rules=None, policy=None, transport=None, config=None):
    transport = transport or ReceiverTransport(system)
    config = config or enrollment(system)
    backend = Backend(config, client_options=client_options(config), transport=transport)
    journal = Journal(path, binding(system, registration))
    if policy is None:
        current = browser(system, "GET", "response/policy").json()
        policy = Policy(policy=current if rules is None else {**current, "rules": rules})
    gate = Gate(journal, backend, policy, capture or default_sensor_config()["capture"], poll_interval=0.01)
    try:
        yield gate, journal, transport
    finally:
        await backend.aclose()
        journal.close()


def held(registration, boundary="tool_call", *, nonce=None):
    nonce = nonce or "held-" + new_id()
    call = event(registration, "tool.call", tool={"name": "Bash", "call_id": "call-" + new_id(), "input": {"command": nonce}})
    if boundary == "prompt":
        target = event(registration, "prompt", text=nonce)
    elif boundary == "assistant_response":
        target = event(registration, "response", text=nonce)
    elif boundary == "tool_output":
        target = event(registration, "tool.result", tool={"name": "Bash", "call_id": call["tool"]["call_id"], "output": nonce})
    else:
        target = event(registration, command={"text": nonce}, tool=call["tool"],
                       file={"path": "/workspace/" + nonce}, network={"host": nonce + ".invalid"})
    context = {"prior_events": [event(registration, "response", text=nonce)],
               "latest_prompt": event(registration, "prompt", text=nonce),
               "matched_tool_call": call if boundary == "tool_output" else None, "gaps": []}
    return HeldBoundary(target["evidence"]["logical_id"], boundary, nonce.encode(), target, context)


class Callback:
    def __init__(self):
        self.raw = []
        self.entered = asyncio.Event()
        self.wait = None

    async def __call__(self, raw):
        self.raw.append(raw)
        self.entered.set()
        if self.wait is not None:
            await self.wait.wait()
        return NativeOutcome("succeeded", exit_code=0)


@pytest.mark.parametrize("source,destination,blocked", [
    ("notes.txt", ".env", True),
    ("app/.env", "notes.txt", True),
    ("notes.txt", "renamed notes.txt", False),
])
@pytest.mark.parametrize("structured", [False, True], ids=["raw", "hook-input"])
def test_offline_managed_patch_renames_enforce_both_paths(tmp_path, source, destination, blocked, structured):
    config = {"server_url": "https://receiver.example", "tenant_id": new_id(),
              "sensor_id": new_id(), "sensor_token": "fixture-token"}
    registration = {"id": new_id(), "external_id": "rename-session", "product": "codex-cli"}
    session = {**{key: config[key] for key in ("server_url", "tenant_id", "sensor_id")},
               "product": registration["product"], "session_id": registration["external_id"],
               "registration_id": registration["id"], "epoch_id": new_id()}
    policy = Policy(policy={"rules": [
        {"id": "docs", "enabled": True, "action": "warn", "match": {"path_glob": "README.md"}},
        {"id": "env", "enabled": True, "action": "deny", "match": {"kinds": ["file.write"], "path_glob": "**/.env"}},
    ]})
    patch = ("*** Begin Patch\n*** Update File: README.md\n@@\n-old\n+new\n"
             f"*** Update File: {source}\n*** Move to: {destination}\n@@\n-old\n+new\n"
             "*** Update File: draft.txt\n*** Move to: final.txt\n@@\n-old\n+new\n*** End Patch")
    inputs = {"command": patch} if structured else patch
    target = event(registration, "tool.call", tool={"name": "apply_patch", "call_id": "rename", "input": inputs})
    raw = json.dumps(inputs).encode() if structured else patch.encode()
    value = HeldBoundary(target["evidence"]["logical_id"], "tool_call", raw, target)

    def offline(request):
        raise httpx.ConnectError("fixture receiver outage", request=request)

    async def scenario():
        backend = Backend(config, client_options=client_options(config), transport=httpx.MockTransport(offline))
        journal = Journal(tmp_path / "journal", session)
        try:
            gate = Gate(journal, backend, policy, default_sensor_config()["capture"])
            callback = Callback()
            result = await gate.gate(value, callback)
            assert result.status == ("blocked" if blocked else "succeeded"), result
            assert callback.raw == ([] if blocked else [raw])
            assert value.event["tool"]["input"] == inputs
        finally:
            await backend.aclose()
            journal.close()

    asyncio.run(scenario())


def test_capture_off_keeps_exact_release_bytes_out_of_wrapper_storage_and_receiver(system, tmp_path):
    registration = registered(system)
    capture = {**default_sensor_config()["capture"], "prompt_text": False,
               "response_text": False, "tool_input": False, "tool_output": False}

    async def scenario():
        callback = Callback()
        values = [held(registration, boundary) for boundary in BOUNDARIES]
        directory = tmp_path / "private-journal"
        async with foundation(system, directory, registration, capture=capture) as (gate, _, transport):
            with pytest.raises((JournalError, OSError)):
                Journal(directory, binding(system, registration))
            for value in values:
                result = await gate.gate(value, callback)
                assert result.status == "succeeded", (value.boundary, result, transport.completed[-1])
            invalid = held(registration)
            private_gap = "invalid-gap-private-" + new_id()
            invalid.context["gaps"] = [private_gap]
            assert (await gate.gate(invalid, callback)).status == "blocked"
            await gate.flush()
            private_close = "invalid-close-private-" + new_id()
            for fields in (
                {"reason": private_close}, {"boundaries": [private_close]}, {"gaps": [private_close]},
            ):
                with pytest.raises(JournalError):
                    await gate.close_session(**{"reason": "session_end", "boundaries": BOUNDARIES, **fields})
            assert await gate.close_session(reason="session_end", boundaries=BOUNDARIES) is True
            assert callback.raw == [value.raw for value in values]
            stored = json.dumps(system.db.many("SELECT target_body,captured_context,prepared_state FROM inline_guardrail_events"), default=str).encode()
            forwarded = json.dumps(transport.completed, default=str).encode()
            provider = json.dumps(system.provider.requests, default=str).encode()
            private_files = b"".join(path.read_bytes() for path in directory.rglob("*") if path.is_file())
            assert private_gap.encode() not in private_files
            assert private_close.encode() not in private_files
            assert directory.stat().st_mode & 0o077 == 0
            assert all(path.stat().st_mode & 0o077 == 0 for path in directory.rglob("*") if path.is_file())
            for value in values:
                for material in (stored, forwarded, provider, private_files):
                    assert value.raw not in material
                    assert hashlib.sha256(value.raw).hexdigest().encode() not in material
                assert value.logical_id.encode() in stored
            assert b"capture_disabled" in stored
            assert b"hmac-sha256-v1:" in forwarded
            assert len(system.provider.requests) == 4

    asyncio.run(scenario())


def test_allow_ask_approve_reject_and_block_release_only_the_bound_callback(system, tmp_path):
    approval_settings(system)
    registration = registered(system)

    async def scenario():
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, transport):
            callback = Callback()
            for score, decision in ((0, None), (50, "approve"), (50, "reject"), (90, None)):
                system.provider.payload = Provider.scored(score)
                value = held(registration)
                before = len(transport.completed)
                pending = asyncio.create_task(gate.gate(value, callback))
                try:
                    checked = (await transport.wait_for("/guardrail-checks", after=before))["response"]
                    if decision:
                        assert pending.done() is False
                        assert value.raw not in callback.raw
                        decide(system, checked["approval"]["id"], decision)
                    result = await asyncio.wait_for(pending, timeout=5)
                finally:
                    if not pending.done():
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
                allowed = score == 0 or decision == "approve"
                assert result.status == ("succeeded" if allowed else "blocked")
                assert (value.raw in callback.raw) is allowed
                await gate.gate(value, callback)
                assert callback.raw.count(value.raw) == int(allowed)
            await gate.flush()
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 2
            assert len(system.provider.requests) == 4

    asyncio.run(scenario())


def test_lost_consume_response_is_uncertain_and_never_releases_after_restart(system, tmp_path):
    registration = registered(system)

    async def scenario():
        callback, value = Callback(), held(registration)
        transport = ReceiverTransport(system)
        transport.drop_once = "/consume"
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, _, _):
            result = await gate.gate(value, callback)
            assert result.status == "uncertain" and callback.raw == []
            original = next(item for item in transport.completed if item["path"].endswith("/consume"))
            assert original["response"]["granted"] is True
        config = enrollment(system)
        backend = Backend(config, client_options=client_options(config), transport=transport)
        journal = Journal(tmp_path / "journal", binding(system, registration))
        try:
            journal.connection.execute("INSERT OR REPLACE INTO metadata VALUES('policy',?)", (b"invalid retired policy",))
            journal.settle()
            delivery = JournalDelivery(journal, backend)
            assert await delivery.flush()
            assert journal.action(value.logical_id)["outcome"] == "uncertain" and callback.raw == []
            attempts = [item for item in transport.completed if item["path"].endswith("/consume")]
            assert all(item["request"] == original["request"] for item in attempts)
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
            assert len(system.provider.requests) == 1
        finally:
            journal.close()
            await backend.aclose()

    asyncio.run(scenario())


def test_changed_payload_and_reenrollment_cannot_reuse_or_redirect_a_journal(system, tmp_path):
    approval_settings(system)
    registration = registered(system)

    async def scenario():
        callback, value = Callback(), held(registration)
        value.event["evidence"]["password"] = "target-private-first"
        value.context["latest_prompt"]["evidence"]["password"] = "context-private-first"
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, transport):
            assert (await gate.gate(value, callback)).status == "succeeded"
            changed_event, changed_context = deepcopy(value.event), deepcopy(value.context)
            changed_event["command"]["text"] = "changed command"
            changed_context["latest_prompt"]["text"] = "changed intent"
            secret_event, secret_context = deepcopy(value.event), deepcopy(value.context)
            secret_event["evidence"]["password"] = "target-private-second"
            secret_context["latest_prompt"]["evidence"]["password"] = "context-private-second"
            for raw, target, context in (
                (value.raw + b" changed", value.event, value.context),
                (value.raw, changed_event, value.context),
                (value.raw, value.event, changed_context),
                (value.raw, secret_event, value.context),
                (value.raw, value.event, secret_context),
            ):
                changed = HeldBoundary(value.logical_id, value.boundary, raw, target, context)
                result = await gate.gate(changed, callback)
                assert result.status == "blocked" and result.reason == "payload_changed"
            assert callback.raw == [value.raw]
            system.provider.payload = Provider.scored(50)
            waiting = held(registration)
            waiting.context["latest_prompt"]["evidence"]["password"] = "private-before-consent"
            before = len(transport.completed)
            pending = asyncio.create_task(gate.gate(waiting, callback))
            try:
                checked = (await transport.wait_for("/guardrail-checks", after=before))["response"]
                waiting.context["latest_prompt"]["evidence"]["password"] = "private-after-consent"
                decide(system, checked["approval"]["id"])
                result = await asyncio.wait_for(pending, timeout=5)
                assert result.status == "blocked" and result.reason == "payload_changed"
            finally:
                if not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
            assert callback.raw == [value.raw]
            assert await gate.flush() is True
            outcome = system.db.scalar(
                "SELECT r.outcome FROM guardrail_releases r JOIN inline_guardrail_events e ON e.id=r.guardrail_event_id WHERE e.logical_id=$1",
                waiting.logical_id,
            )
            assert outcome == "not_executed"
            assert await gate.close_session(reason="session_end", boundaries=BOUNDARIES) is True
        foreign = enrollment(system, "foreign_sensor")
        rebound = {**binding(system, registration), **{key: foreign[key] for key in ("server_url", "tenant_id", "sensor_id")}}
        with pytest.raises(JournalError):
            Journal(tmp_path / "journal", rebound)
        transport = ReceiverTransport(system)
        async with foundation(system, tmp_path / "journal", registration, config=foreign, transport=transport) as (gate, _, _):
            result = await gate.gate(value, callback)
            await gate.flush()
            assert result.status == "blocked"
            assert transport.completed == []
        assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 2
        assert callback.raw == [value.raw]
        assert (tmp_path / "journal" / "journal.lock").is_file()
        (tmp_path / "journal" / "journal.sqlite3").unlink()
        with pytest.raises(JournalError, match="journal_lost"):
            Journal(tmp_path / "journal", binding(system, registration))
        assert len(system.provider.requests) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize("abandon_display", [False, True])
def test_declared_model_and_display_deliveries_share_one_assessment_and_release(system, tmp_path, abandon_display):
    registration = registered(system)

    async def scenario():
        value = held(registration, "tool_output")
        model, display = Callback(), Callback()
        consumers = ("model", "display")
        deliveries = [HeldBoundary(
            value.logical_id, value.boundary, value.raw, value.event, value.context,
            delivery_id=name, deliveries=consumers,
        ) for name in consumers]
        async with foundation(system, tmp_path / "journal", registration) as (gate, journal, _):
            if abandon_display:
                assert (await gate.gate(deliveries[0], model)).status == "succeeded"
                assert journal.delivery(value.logical_id, "display")["outcome"] is None
                # Native death can occur before this declared consumer ever
                # enters Gate. No callback task exists to cancel here.
                await gate.settle()
                assert journal.delivery(value.logical_id, "display")["outcome"] == "not_executed"
                assert journal.delivery(value.logical_id, "model")["outcome"] == "succeeded"
                assert (await gate.gate(deliveries[1], display)).status != "succeeded"
                assert display.raw == []
                assert await gate.close_session(reason="process_exit", boundaries=BOUNDARIES) is True
                assert system.db.scalar("SELECT outcome FROM guardrail_releases") == "failed"
            else:
                results = await asyncio.gather(gate.gate(deliveries[0], model), gate.gate(deliveries[1], display))
                assert all(result.status == "succeeded" for result in results)
                assert results[0].release_id == results[1].release_id
                for delivery, callback in zip(deliveries, (model, display), strict=True):
                    await gate.gate(delivery, callback)
                    assert callback.raw == [value.raw]
                extra = Callback()
                changed = HeldBoundary(
                    value.logical_id, value.boundary, value.raw, value.event, value.context,
                    delivery_id="extra", deliveries=(*consumers, "extra"),
                )
                rejected = await gate.gate(changed, extra)
                assert rejected.status == "blocked" and rejected.reason == "payload_changed"
                assert extra.raw == []
                await gate.flush()
        assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 1
        assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
        assert system.db.scalar("SELECT count(*) FROM model_usage") == 1
        assert len(system.provider.requests) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("stage", ["approval", "dispatch"])
def test_cancelled_consumer_cannot_be_released_by_late_consent_or_restart(system, tmp_path, stage):
    approval_settings(system)
    registration = registered(system)
    system.provider.payload = Provider.scored(50 if stage == "approval" else 0)

    async def scenario():
        callback, value = Callback(), held(registration)
        callback.wait = asyncio.Event()
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, transport):
            pending = asyncio.create_task(gate.gate(value, callback))
            try:
                checked = (await transport.wait_for("/guardrail-checks"))["response"]
                if stage == "dispatch":
                    await asyncio.wait_for(callback.entered.wait(), timeout=5)
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
                if stage == "approval":
                    decide(system, checked["approval"]["id"])
                assert callback.raw == ([value.raw] if stage == "dispatch" else [])
            finally:
                if not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
        callback.wait.set()
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, _):
            result = await gate.gate(value, callback)
            await gate.flush()
            assert result.status == ("uncertain" if stage == "dispatch" else "cancelled")
            assert callback.raw == ([value.raw] if stage == "dispatch" else [])
            assert len(system.provider.requests) == 1

    asyncio.run(scenario())


def test_backend_outage_allows_only_without_cached_restriction_or_explicit_auth_denial(system, tmp_path):
    registration = registered(system)

    async def scenario():
        for action in ("allow", "warn", "ask", "deny"):
            callback = Callback()
            transport = ReceiverTransport(system)
            transport.offline = True
            rules = [] if action == "allow" else [{
                "id": "cached-rule", "name": "Cached restriction", "enabled": True,
                "action": action, "match": {"kinds": ["command"]},
            }]
            value = held(registration)
            async with foundation(system, tmp_path / action, registration, rules=rules, transport=transport) as (gate, _, _):
                result = await asyncio.wait_for(gate.gate(value, callback), timeout=5)
                if action in ("allow", "warn"):
                    assert result.status == "succeeded" and result.reason == "backend_unavailable"
                    assert result.warned is (action == "warn")
                    assert callback.raw == [value.raw]
                    transport.offline = False
                    await gate.flush()
                else:
                    assert result.status == "blocked" and callback.raw == []
        denied = {**enrollment(system), "sensor_token": "invalid-device-token"}
        for failure in ("auth-denied", "auth-body-timeout", "certificate-denied"):
            callback, transport = Callback(), ReceiverTransport(system)
            transport.broken_body_statuses = {401, 403} if failure == "auth-body-timeout" else set()
            transport.certificate_error = failure == "certificate-denied"
            config = enrollment(system) if transport.certificate_error else denied
            async with foundation(system, tmp_path / failure, registration, config=config, transport=transport) as (gate, _, _):
                result = await gate.gate(held(registration), callback)
                assert result.status == "blocked" and callback.raw == []
                if transport.certificate_error:
                    assert transport.completed == []
                else:
                    assert any(item["status"] in (401, 403) for item in transport.completed)
        transport = ReceiverTransport(system)
        transport.broken_body_statuses = {409}
        config = enrollment(system)
        backend = Backend(config, client_options=client_options(config), transport=transport)
        try:
            with pytest.raises(BackendRejected) as conflict:
                await backend.bind(registration["id"], "different-native-session")
            assert conflict.value.status == 409
            assert transport.completed[-1]["status"] == 409
        finally:
            await backend.aclose()
        assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 0
        assert system.provider.requests == []
        retained = system.db.many("SELECT body FROM events")
        assert "backend_unavailable" in json.dumps(retained)

    asyncio.run(scenario())


@pytest.mark.parametrize("source", ["gate", "flush", "missing-registration", "delayed-status"])
def test_auth_denial_survives_new_actions_and_restart_until_verified_recovery(system, tmp_path, source):
    registration = registered(system)
    if source == "missing-registration":
        registration = {**registration, "id": new_id()}

    class PauseValidStatus(ReceiverTransport):
        def __init__(self, system):
            super().__init__(system)
            self.once = source == "delayed-status"
            self.received, self.resume = asyncio.Event(), asyncio.Event()

        async def handle_async_request(self, request):
            response = await super().handle_async_request(request)
            if self.once and request.url.path.endswith("/status"):
                self.once = False
                self.received.set()
                await self.resume.wait()
            return response

    async def scenario():
        transport, callback = PauseValidStatus(system), Callback()
        initial = enrollment(system)
        if source in ("gate", "flush"):
            initial = {**initial, "sensor_token": "expired-synthetic-token"}
        directory = tmp_path / "journal"
        first = held(registration)
        async with foundation(system, directory, registration, transport=transport, config=initial) as (gate, _, _):
            if source == "delayed-status":
                pending = asyncio.create_task(gate.gate(first, callback))
                try:
                    await asyncio.wait_for(transport.received.wait(), timeout=5)
                    assert transport.completed[-1]["status"] == 200
                    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["sensor"][0]["id"])
                    assert await gate.flush() is False
                    transport.offline = True
                    transport.resume.set()
                    assert (await asyncio.wait_for(pending, timeout=5)).status == "blocked"
                finally:
                    transport.resume.set()
                    if not pending.done():
                        pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
            elif source == "flush":
                transport.offline = True
                assert (await gate.gate(first, callback)).status == "succeeded"
                transport.offline = False
                assert await gate.flush() is False
            else:
                assert (await gate.gate(first, callback)).status == "blocked"
            denied_statuses = (404,) if source == "missing-registration" else (401, 403)
            assert any(item["status"] in denied_statuses for item in transport.completed)
            executed = [first.raw] if source == "flush" else []
            assert callback.raw == executed
            transport.offline = True
            blocked = held(registration)
            assert (await gate.gate(blocked, callback)).status == "blocked"
            assert callback.raw == executed
        # Corrected credentials do not establish recovery until a verified
        # response arrives for this exact persisted registration and epoch.
        async with foundation(system, directory, registration, transport=transport) as (gate, _, _):
            assert (await gate.gate(held(registration), callback)).status == "blocked"
            await gate.gate(first, callback)
            assert callback.raw == executed
            transport.offline = False
            if source == "missing-registration":
                assert (await gate.gate(held(registration), callback)).status == "blocked"
                assert transport.completed[-1]["status"] == 404
                transport.offline = True
                assert (await gate.gate(held(registration), callback)).status == "blocked"
                assert callback.raw == [] and system.provider.requests == []
                return
            if source == "delayed-status":
                system.db.execute("UPDATE sensors SET disabled=false WHERE id=$1", system.sensors["sensor"][0]["id"])
            recovered = held(registration)
            assert (await gate.gate(recovered, callback)).status == "succeeded"
            executed.append(recovered.raw)
            assert (await gate.gate(blocked, callback)).status == "blocked"
            assert callback.raw == executed
            transport.offline = True
            unrestricted = held(registration)
            result = await gate.gate(unrestricted, callback)
            assert result.status == "succeeded" and result.reason == "backend_unavailable"
            assert callback.raw == [*executed, unrestricted.raw]
            transport.offline = False
            assert await gate.flush() is True
        assert len(system.provider.requests) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("action", ["ask", "deny"])
def test_concurrently_learned_policy_fences_outage_and_survives_stale_cache_reopen(system, tmp_path, action):
    registration = registered(system)
    stale = browser(system, "GET", "response/policy").json()

    class PauseFirstCheck(ReceiverTransport):
        def __init__(self, system):
            super().__init__(system)
            self.paused, self.resume = asyncio.Event(), asyncio.Event()
            self.once = True

        async def handle_async_request(self, request):
            if self.once and request.url.path.endswith("/guardrail-checks"):
                self.once = False
                self.paused.set()
                await self.resume.wait()
            return await super().handle_async_request(request)

    async def scenario():
        transport, callback = PauseFirstCheck(system), Callback()
        directory = tmp_path / "journal"
        original = held(registration)
        async with foundation(system, directory, registration, transport=transport) as (gate, _, _):
            pending = asyncio.create_task(gate.gate(original, callback))
            try:
                await asyncio.wait_for(transport.paused.wait(), timeout=5)
                changed = browser(system, "PUT", "response/policy", {"rules": [{
                    "id": "new-restriction", "name": "Learned restriction", "enabled": True,
                    "action": action, "match": {"kinds": ["command"]},
                }]})
                assert changed.status_code == 200, changed.text
                assert (await gate.gate(held(registration), callback)).status == "blocked"
                assert gate.policy.version == changed.json()["version"] > stale["version"]
                assert gate.policy.evaluate(original.event)["action"] == action
                transport.offline = True
                transport.resume.set()
                assert (await asyncio.wait_for(pending, timeout=5)).status == "blocked"
                assert callback.raw == []
            finally:
                if not pending.done():
                    pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
        async with foundation(
            system, directory, registration, transport=transport, policy=Policy(policy=deepcopy(stale)),
        ) as (gate, _, _):
            assert (await gate.gate(original, callback)).status == "blocked"
            assert (await gate.gate(held(registration), callback)).status == "blocked"
            assert callback.raw == []
            allowed = browser(system, "PUT", "response/policy", {"rules": []})
            assert allowed.status_code == 200, allowed.text
            transport.offline = False
            recovered = held(registration)
            assert (await gate.gate(recovered, callback)).status == "succeeded"
            assert gate.policy.version == allowed.json()["version"]
            transport.offline = True
            unrestricted = held(registration)
            assert (await gate.gate(unrestricted, callback)).status == "succeeded"
            assert callback.raw == [recovered.raw, unrestricted.raw]
        assert len(system.provider.requests) == 2

    asyncio.run(scenario())


def test_delivery_ack_loss_replays_dense_receipts_and_persists_one_close(system, tmp_path):
    registration = registered(system)

    async def scenario():
        callback, value = Callback(), held(registration)
        transport = ReceiverTransport(system)
        transport.drop_once = "/delivery"
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, _, _):
            assert (await gate.gate(value, callback)).status == "succeeded"
            await gate.flush()
            await gate.close_session(reason="session_end", boundaries=BOUNDARIES)
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, _, _):
            await gate.flush()
            await gate.close_session(reason="session_end", boundaries=BOUNDARIES)
        deliveries = [item for item in transport.completed if item["path"].endswith("/delivery")]
        assert len(deliveries) >= 2
        original = deliveries[0]["request"]["records"]
        retried = {record["record_id"]: record for item in deliveries[1:] for record in item["request"]["records"]}
        assert all(retried[record["record_id"]] == record for record in original)
        assert any(item["response"]["duplicates"] > 0 for item in deliveries[1:])
        rows = system.db.many(
            "SELECT sequence,record_id,kind FROM session_delivery_receipts WHERE registration_id=$1 ORDER BY sequence",
            registration["id"],
        )
        dense = [row for row in rows if row["sequence"] is not None]
        assert [row["sequence"] for row in dense] == list(range(1, len(dense) + 1))
        assert {row["kind"] for row in dense} >= {"target", "outcome"}
        assert len({row["record_id"] for row in dense}) == len(dense)
        closes = [row for row in rows if row["sequence"] is None]
        assert len(closes) == 1
        assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
        assert callback.raw == [value.raw]
        assert len(system.provider.requests) == 1

    asyncio.run(scenario())


def test_offline_first_session_never_acquires_verified_ownership_after_recovery(system, tmp_path):
    online = registered(system)
    offline = {**online, "id": None, "external_id": "offline-" + new_id(), "delivery_epoch": new_id()}

    async def scenario():
        callback, value = Callback(), held(offline)
        for item in [value.event, *value.context["prior_events"], value.context["latest_prompt"]]:
            item["session"].pop("registration_id", None)
        transport = ReceiverTransport(system)
        transport.offline = True
        directory = tmp_path / "offline"
        async with foundation(system, directory, offline, transport=transport) as (gate, _, _):
            for name in ("model", "display"):
                delivered = HeldBoundary(
                    value.logical_id, value.boundary, value.raw, value.event, value.context,
                    delivery_id=name, deliveries=("model", "display"),
                )
                assert (await gate.gate(delivered, callback)).status == "succeeded"
            assert callback.raw == [value.raw, value.raw]
            for action in ("deny", "ask"):
                gate.policy.set({**gate.policy.policy, "rules": []})
                restricted, released = held(offline), Callback()
                for item in [restricted.event, *restricted.context["prior_events"], restricted.context["latest_prompt"]]:
                    item["session"].pop("registration_id", None)
                deliveries = [HeldBoundary(
                    restricted.logical_id, restricted.boundary, restricted.raw, restricted.event, restricted.context,
                    delivery_id=name, deliveries=("model", "display"),
                ) for name in ("model", "display")]
                assert (await gate.gate(deliveries[0], released)).status == "succeeded"
                gate.policy.set({**gate.policy.policy, "version": gate.policy.version + 1, "rules": [{
                    "id": "new-cached-rule", "name": "Updated cached restriction", "enabled": True,
                    "action": action, "match": {"kinds": ["command"]},
                }]})
                assert (await gate.gate(deliveries[1], released)).status == "blocked"
                assert released.raw == [restricted.raw]
            transport.offline = False
            await gate.flush()
            assert transport.completed == []
        with pytest.raises(JournalError):
            Journal(directory, {**binding(system, offline), "registration_id": online["id"]})
        assert system.db.scalar("SELECT count(*) FROM events") == 0
        # A pre-bootstrap bearer installation can have no trusted tenant ID.
        # It is permanently local, even while a receiver is reachable again.
        unscoped = {**binding(system, offline), "tenant_id": None, "epoch_id": new_id()}
        local_config = {**enrollment(system), "tenant_id": None}
        local_transport = ReceiverTransport(system)
        local_backend = Backend(local_config, client_options=client_options(local_config), transport=local_transport, local_only=True)
        local_path = tmp_path / "unscoped-offline"
        local_journal = Journal(local_path, unscoped)
        try:
            assert local_backend.http is None
            local_gate = Gate(local_journal, local_backend, Policy(), default_sensor_config()["capture"])
            assert (await local_gate.gate(held(offline), Callback())).status == "succeeded"
            assert await local_gate.flush() is False
            assert local_transport.completed == []
        finally:
            await local_backend.aclose()
            local_journal.close()
        with pytest.raises(JournalError):
            Journal(local_path, {**unscoped, "tenant_id": system.tenant["id"]})
        with pytest.raises(JournalError):
            Journal(tmp_path / "invalid-unscoped", {**unscoped, "registration_id": online["id"]})
        async with foundation(system, tmp_path / "fresh-online", online) as (gate, _, _):
            assert (await gate.gate(held(online), Callback())).status == "succeeded"
            await gate.flush()
        assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 1
        assert len(system.provider.requests) == 1

    asyncio.run(scenario())


def test_capture_that_fits_config_is_bounded_for_the_receiver_target_envelope(system, tmp_path):
    detection_settings(system)
    registration = registered(system)

    async def scenario():
        value = held(registration, "prompt", nonce="large-permitted-prompt:" + "x" * 9000 + ":permitted-tail")
        callback = Callback()
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, transport):
            result = await gate.gate(value, callback)
            assert result.status == "succeeded", (result, transport.completed[-1])
            assert callback.raw == [value.raw]
            assert len(system.provider.requests) == 1
            checked = next(item["request"] for item in transport.completed if item["path"].endswith("/guardrail-checks"))
            assert len(json.dumps(checked["target"], ensure_ascii=False, separators=(",", ":")).encode()) <= 8 << 10
            assert "content_truncated" in checked["target"]["evidence"]["gaps"]
            await gate.flush()
            await gate.close_session(reason="session_end", boundaries=BOUNDARIES)
            ordinary = system.db.many("SELECT body FROM events WHERE body->'evidence'->>'logical_id'=$1", value.logical_id)
            assert any(row["body"].get("text") == value.raw.decode() for row in ordinary)
            receipts = system.db.many("SELECT captured_body FROM session_delivery_receipts WHERE registration_id=$1", registration["id"])
            assert any(row["captured_body"].get("text") == value.raw.decode() for row in receipts if row["captured_body"])
            state = finalized(system, registration)
            retained = snapshot_page(system, state["snapshot_id"], limit=500)
            assert any(item["body"].get("text") == value.raw.decode() for item in retained["items"] if item["kind"] == "observation")
            assert state["counts"]["logical_targets"] == 1

    asyncio.run(scenario())


def test_new_static_policy_still_blocks_when_client_redaction_hides_its_match(system, tmp_path):
    registration = registered(system)
    path = f"session-registrations/{registration['id']}/status"
    assert "policy" not in sensor_post(system, path)
    for value, device, status in ((1, "sensor", 400), (True, "peer_sensor", 404)):
        denied = system.client.post(
            "/ingest/v1/" + path, json={"include_policy": value}, headers=system.headers[device],
        )
        assert denied.status_code == status, denied.text
        assert set(denied.json()) == {"error"}

    async def scenario():
        value = held(registration, nonce="printf password=review-secret")
        callback = Callback()
        async with foundation(system, tmp_path / "journal", registration) as (gate, _, transport):
            changed = browser(system, "PUT", "response/policy", {"rules": [{
                "id": "fresh-deny", "name": "Fresh sensitive-command deny", "enabled": True,
                "action": "deny", "match": {"kinds": ["command"], "command_regex": "review-secret"},
            }]})
            assert changed.status_code == 200, changed.text
            result = await gate.gate(value, callback)
            assert result.status == "blocked", result
            assert callback.raw == []
            checked = next(item for item in transport.completed if item["path"].endswith("/guardrail-checks"))
            assert checked["request"]["policy_version"] == changed.json()["version"]
            assert checked["response"]["decision"]["action"] == "block"
            assert len(system.provider.requests) == 1

    asyncio.run(scenario())


def test_known_auth_denial_stays_effective_for_later_declared_consumer_during_outage(system, tmp_path):
    registration = registered(system)

    async def scenario():
        value = held(registration)
        transport = ReceiverTransport(system)
        consumers = ("model", "display", "mirror")
        async with foundation(system, tmp_path / "journal", registration, transport=transport) as (gate, _, _):
            for index, name in enumerate(consumers):
                if index == 1:
                    system.db.execute("UPDATE sensors SET disabled=true WHERE id=$1", system.sensors["sensor"][0]["id"])
                elif index == 2:
                    transport.offline = True
                callback = Callback()
                delivered = HeldBoundary(
                    value.logical_id, value.boundary, value.raw, value.event, value.context,
                    delivery_id=name, deliveries=consumers,
                )
                result = await gate.gate(delivered, callback)
                assert result.status == ("succeeded" if index == 0 else "blocked"), (name, result)
                assert callback.raw == ([value.raw] if index == 0 else [])
        assert len(system.provider.requests) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("tool", ["Bash", "apply_patch"])
def test_hidden_local_ask_remains_a_usable_authenticated_approval(system, tmp_path, tool):
    approval_settings(system)
    registration = registered(system)
    changed = browser(system, "PUT", "response/policy", {"rules": [{
        "id": "hidden-ask", "name": "Approve sensitive command", "enabled": True,
        "action": "ask", "match": ({"kinds": ["command"], "command_regex": "review-secret"}
                                   if tool == "Bash" else {"kinds": ["file.write"], "path_glob": "private/review-secret"}),
    }]})
    assert changed.status_code == 200, changed.text
    capture = {**default_sensor_config()["capture"], "prompt_text": False,
               "response_text": False, "tool_input": False, "tool_output": False}

    def value_for(path="private/review-secret"):
        value = held(registration, nonce="printf password=review-secret")
        if tool == "apply_patch":
            patch = "*** Begin Patch\n*** Add File: benign.txt\n+first\n*** Add File: " + path + "\n+second\n*** End Patch"
            target = event(registration, "tool.call", tool={"name": tool, "call_id": new_id(), "input": patch})
            value = HeldBoundary(target["evidence"]["logical_id"], "tool_call", patch.encode(), target, value.context)
        return value

    async def scenario():
        value = value_for()
        callback = Callback()
        async with foundation(system, tmp_path / "journal", registration, capture=capture) as (gate, _, transport):
            if tool == "apply_patch":
                transport.offline = True
                original_policy = deepcopy(gate.policy.policy)
                for action in ("ask", "deny"):
                    cached = deepcopy(original_policy)
                    cached["rules"][0]["action"] = action
                    gate.policy.set(cached)
                    denied = Callback()
                    assert (await gate.gate(value_for(), denied)).status == "blocked"
                    assert denied.raw == []
                    benign, released = value_for("public/second.txt"), Callback()
                    assert (await gate.gate(benign, released)).status == "succeeded"
                    assert released.raw == [benign.raw]
                assert transport.completed == [] and system.provider.requests == []
                gate.policy.set(original_policy)
                transport.offline = False
            pending = asyncio.create_task(gate.gate(value, callback))
            try:
                checked = (await transport.wait_for("/guardrail-checks"))["response"]
                assert checked["decision"]["action"] == "ask"
                assert pending.done() is False and callback.raw == []
                decide(system, checked["approval"]["id"])
                assert (await asyncio.wait_for(pending, timeout=5)).status == "succeeded"
            finally:
                if not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
            await gate.flush()
            assert callback.raw == [value.raw]
            assert value.raw.decode() not in json.dumps(transport.completed)
            assert "review-secret" not in json.dumps(system.provider.requests)
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
            assert len(system.provider.requests) == 1
            system.provider.payload = Provider.scored(90)
            blocked = Callback()
            stricter = await gate.gate(value_for(), blocked)
            assert stricter.status == "blocked" and blocked.raw == []
            assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
            assert len(system.provider.requests) == 2

    asyncio.run(scenario())


def test_policy_floor_aliases_bind_requests_and_fence_older_check_consumption(system):
    approval_settings(system)
    registration = registered(system)
    value = payload(system, registration)
    allowed = check(system, value)
    assert allowed["decision"]["action"] == "allow"
    for floor in (None, False, "allow"):
        check(system, {**value, "request_id": new_id(), "policy_floor": floor}, expected=400)
    ask_value = {**value, "request_id": new_id(), "policy_floor": "ask"}
    asked = check(system, ask_value)
    assert asked["assessment"] == allowed["assessment"]
    assert asked["decision"]["action"] == "ask"
    assert check(system, {**ask_value, "policy_floor": "block"}, expected=409)["error"]["code"] == "payload_changed"
    assert check(system, value, expected=409)["error"]["code"] == "policy_floor_changed"
    assert consume(system, allowed, expected=409)["error"]["code"] == "policy_floor_changed"
    alias = check(system, {**value, "request_id": new_id()})
    assert alias["decision"]["action"] == "ask"
    assert alias["approval"]["id"] == asked["approval"]["id"]
    decide(system, asked["approval"]["id"])
    stronger = {**value, "request_id": new_id(), "policy_floor": "block"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        with system.db.transaction() as gate:
            system.db.one("SELECT id FROM inline_guardrail_events WHERE event_id=$1 FOR UPDATE", value["target"]["id"], conn=gate)
            blocking = pool.submit(check, system, stronger)
            wait_for_blocker(system.db, gate.info.backend_pid)
            blocking_pid = system.db.scalar("SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))", gate.info.backend_pid)
            consuming = pool.submit(consume, system, asked, expected=409)
            wait_for_blocker(system.db, blocking_pid)
            gate.execute("SELECT pg_sleep(0.250)")
        assert blocking.result(timeout=5)["decision"]["action"] == "block"
        assert consuming.result(timeout=5)["error"]["code"] == "action_blocked"
    assert check(system, ask_value, expected=409)["error"]["code"] == "action_blocked"
    assert check(system, {**value, "request_id": new_id()})["decision"]["action"] == "block"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 0
    assert system.db.scalar("SELECT count(*) FROM inline_guardrail_events") == 1
    assert len(system.provider.requests) == system.db.scalar("SELECT count(*) FROM model_usage") == 1


def test_consumed_floor_request_replays_receipt_without_grant_or_new_consent(system):
    approval_settings(system)
    registration = registered(system)
    value = {**payload(system, registration), "policy_floor": "ask"}
    asked = check(system, value)
    decide(system, asked["approval"]["id"])
    request = {"request_id": new_id(), "action_commitment": asked["action_commitment"]}
    release = consume(system, asked, request)
    assert release["granted"] is True
    assert check(system, {**value, "request_id": new_id(), "policy_floor": "block"}, expected=409)["error"]["code"] == "action_already_consumed"
    replayed = consume(system, asked, request, expected=200)
    assert replayed["id"] == release["id"]
    assert replayed["replayed"] is True and replayed["granted"] is False
    assert consume(system, asked, expected=409)["error"]["code"] == "action_already_consumed"
    assert system.db.scalar("SELECT count(*) FROM guardrail_releases") == 1
    assert system.db.scalar("SELECT count(*) FROM guardrail_approvals") == 1
    assert len(system.provider.requests) == system.db.scalar("SELECT count(*) FROM model_usage") == 1
