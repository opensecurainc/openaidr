"""Tenant controller adapter for the selected, authenticated investigation service."""

from functools import partial
import threading
import time
from uuid import UUID, uuid5

from openaidr_api_client.contracts import investigator_profile as native
from openaidr_api_client.client import SyncIntelligenceClient
from .intelligence import selected_connection
from openaidr_api_client.contracts import investigations as wire
from . import session_investigator as inv
from .investigation_bridge import Bridge


def runtime(st, config, *, tenant_id=None, benchmark_owner_tenant_id=None):
    connection = selected_connection(config, st)
    if tenant_id is not None and connection and connection.tenant_id != tenant_id:
        connection = None
    return RemoteRuntime(st, connection, benchmark_owner_tenant_id=benchmark_owner_tenant_id)


class RemoteRuntime:
    remote = True

    def __init__(self, st, connection, *, benchmark_owner_tenant_id=None, transport=None):
        self.st, self.connection, self.benchmark_owner = st, connection, benchmark_owner_tenant_id
        self.client = SyncIntelligenceClient.from_connection(connection, transport=transport) if connection else None
        self.bridge, self.job, self.profile = None, None, None
        self._deadline = 0
        self._closed = threading.Event()
        self._done = False
        self._callbacks = None
        self.checkpoint = lambda: None

    prefix = "/v1/investigations"

    def _request(self, path, value, *, method="POST", statuses=(200,), cleanup=False, deadline=None):
        inv._need(self.client is not None, "runtime_unavailable")
        remaining = self._deadline - time.monotonic() if self._deadline else 10
        if deadline is not None:
            remaining = min(remaining, deadline - time.monotonic())
        inv._need(cleanup or (not self._closed.is_set() and remaining > 0), "claim_expired")
        return self.client.request(path, value, wire.MAX_BODY, 5 if cleanup else min(10, remaining),
                                   method=method, accepted_status=statuses, decoder=wire.load)

    def ready(self, model=None):
        unavailable = dict(ready=False, reason="runtime_unavailable", supported_models=[])
        if model is not None and model != native.MODEL:
            return dict(unavailable, reason="model_unavailable")
        if self.client is None or self._closed.is_set():
            return unavailable
        try:
            if self.profile is None:
                deadline = time.monotonic() + 10
                response = self._request("/v1/investigations/runtime", None, method="GET", deadline=deadline)
                result = wire.RuntimeReadiness.model_validate(response).model_dump()
                if not result["ready"]:
                    return unavailable
                profile = result["profile"]
                inv._need(profile and wire.digest(profile) == result["runtime_profile_sha256"])
                inv._need(native.MODEL in result["supported_models"])
                expected = {os + "/" + arch: digest for (os, arch), digest in native.EXECUTABLE_DIGESTS.items()}
                inv._need(expected.get(profile["platform"]) == profile["executable_sha256"])
                self.profile, self.build = profile, result["build"]
            return dict(self.profile, ready=True, reason="", supported_models=[native.MODEL],
                        origin=self.connection.origin, build=self.build)
        except Exception:
            return unavailable

    def bind_attempt(self, claim, prepared):
        self._deadline = time.monotonic() + prepared["remaining_seconds"]
        self.bridge = Bridge(self.st, claim, self.connection, self.profile,
                             benchmark_owner_tenant_id=self.benchmark_owner)
        request = self.bridge.prepare_binding()
        # A repeated create uses the persisted identity and exact original bytes.
        # It cannot start a native step or allocate a second paid attempt.
        try:
            created = self._request(self.prefix, request, statuses=(200, 202))
        except Exception:
            created = self._request(self.prefix, request, statuses=(200, 202))
        self.job = self.bridge.attach(created)
        for message in self.bridge.recovery()["messages"]:
            self._send(message)

    def _exchange(self, message, *, cleanup=False):
        result = wire.ExchangeResult.model_validate(self._request(
            self.prefix + "/" + self.job + "/exchange", message, cleanup=cleanup)).model_dump()
        inv._need(result["id"] == self.job, "invalid_result")
        return result

    def _send(self, message, *, rebuild=None, cleanup=False):
        try:
            result = self._exchange(message, cleanup=cleanup)
        except Exception:
            result = self._exchange(dict(type="poll", ack_for=message["message_id"]), cleanup=cleanup)
            if result["ack"] is None:
                # Reconstruct sensitive messages through a fresh tenant fence.
                # Never retransmit cached evidence or an expired permission.
                if rebuild is not None:
                    message = rebuild()
                result = self._exchange(message, cleanup=cleanup)
        inv._need(result["ack"] is not None, "incomplete_coverage")
        self.bridge.acknowledge(message, result["ack"])
        return result

    def run(self, *, step, tool_callback, call_admission, call_finish, deadline):
        inv._need(self.bridge is not None)
        self._deadline = min(self._deadline, deadline)
        self._callbacks = dict(tool_callback=tool_callback, call_admission=call_admission, call_finish=call_finish)
        create = partial(self.bridge.step_message, step)
        state = self._send(create(), rebuild=create)
        while True:
            operation = state["pending"]
            if operation:
                inv._need(operation["step_id"] == step["id"], "invalid_result")
                reply = partial(self.bridge.reply, operation, **self._callbacks)
                message = reply()
                self.checkpoint()
                state = self._send(message, rebuild=reply)
                if state["state"] in wire.TERMINAL:
                    raise inv.InvestigationStopped(state["stop_code"] or "runtime_unavailable")
                # The same pending operation can still be waiting for worker
                # consumption after the response acknowledgement. Poll first.
                state = self._exchange(dict(type="poll", ack_for=None))
                if state["pending"] and state["pending"]["operation_id"] == operation["operation_id"]:
                    self._closed.wait(0.25)
                continue
            if state["state"] in wire.TERMINAL:
                raise inv.InvestigationStopped(state["stop_code"] or "runtime_unavailable")
            if state["step_result"]:
                result = state["step_result"]
                return dict(result, text=self.bridge.verify_result(step["id"], result))
            self._closed.wait(0.25)
            state = self._exchange(dict(type="poll", ack_for=None))

    def accept_step(self, step, result, complete_callback):
        self._send(self.bridge.accept_step(step["id"], result, complete_callback))

    def finish(self, publish_callback):
        result, message = self.bridge.finish(publish_callback)
        # Publication and the stable finish message are already committed.
        # A lost final acknowledgement must not replace the published report.
        self._done = True
        try:
            self._send(message, cleanup=True)
        except Exception:
            pass
        return result

    def close(self):
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            if self.job and not self._done:
                self._request(self.prefix + "/" + self.job + "/cancel",
                              dict(message_id=str(uuid5(UUID(self.job), "tenant-cancel-v1")), code="cancelled"), cleanup=True)
                # Persisted late receipts are handled even though continuation
                # is forbidden. The worker never releases output on this path.
                state = self._exchange(dict(type="poll", ack_for=None), cleanup=True)
                operation = state["pending"]
                if operation and operation["kind"] == "finish_call" and self._callbacks:
                    self._send(self.bridge.reply(operation, **self._callbacks), cleanup=True)
        except Exception:
            pass
        finally:
            if self.client is not None:
                self.client.close()


class Recovery:
    """Reconcile one expired attempt per tick without starting another native step."""

    def __init__(self, st, connection, *, transport=None):
        self.st, self.connection, self.transport = st, connection, transport
        self.after = "00000000-0000-0000-0000-000000000000"

    def tick(self):
        rows = self.st.many("""SELECT b.*,a.claim_token,a.job_id,a.state AS attempt_state
            FROM session_investigation_remote_bindings b
            JOIN session_investigation_attempts a ON a.id=b.attempt_id
            WHERE b.origin=$1 AND b.owner_tenant_id=$2 AND b.attempt_id>$3::uuid
              AND b.remote_id IS NOT NULL AND b.created_at>clock_timestamp()-interval '30 days'
              AND (a.completed_at IS NOT NULL OR a.deadline_at<=clock_timestamp())
              AND (EXISTS(SELECT 1 FROM session_investigation_remote_messages m
                          WHERE m.attempt_id=b.attempt_id AND m.ack_revision IS NULL)
                   OR EXISTS(SELECT 1 FROM session_investigation_requests r JOIN model_usage u ON u.id=r.usage_id
                             WHERE r.attempt_id=b.attempt_id AND u.cost_usd IS NULL)
                   OR a.state IN ('reserved','dispatched'))
            ORDER BY b.attempt_id LIMIT 1""", self.connection.origin, self.connection.tenant_id, self.after)
        if not rows:
            self.after = "00000000-0000-0000-0000-000000000000"
            return False
        row = rows[0]
        self.after = row["attempt_id"]
        profile = wire.RuntimeProfile.model_validate(row["profile"]).model_dump()
        claim = {key: row[key] for key in ("attempt_id", "tenant_id", "job_id", "claim_token")}
        remote = RemoteRuntime(self.st, self.connection, transport=self.transport)
        remote.profile, remote.job = profile, row["remote_id"]
        remote.bridge = Bridge(self.st, claim, self.connection, profile)
        try:
            recovery = remote.bridge.recovery()
            if recovery["publication"] is not None:
                remote._done = True
                for message in recovery["messages"]:
                    remote._send(message, cleanup=True)
                return True
            inv.stop_attempt(self.st, claim, "runtime_unavailable")
            state = remote._exchange(dict(type="poll", ack_for=None), cleanup=True)
            op = state["pending"]
            if op and op["kind"] == "finish_call":
                old = self.st.many("""SELECT message FROM session_investigation_remote_messages
                    WHERE attempt_id=$1 AND operation_id=$2""", row["attempt_id"], op["operation_id"])
                if old:
                    # The accounting transaction already committed. Resolve its
                    # delivery only; an old true reply cannot authorize new work.
                    message = old[0]["message"]
                    ack = remote._exchange(dict(type="poll", ack_for=message["message_id"]), cleanup=True)["ack"]
                    if ack:
                        remote.bridge.acknowledge(message, ack)
                    else:
                        # The receipt committed locally but may never have reached
                        # the service. Stop the original worker before replaying a
                        # historical true reply that could otherwise release output.
                        cancelled = wire.ExchangeResult.model_validate(remote._request(
                            remote.prefix + "/" + remote.job + "/cancel",
                            dict(message_id=str(uuid5(UUID(remote.job), "tenant-cancel-v1")), code="cancelled"),
                            cleanup=True)).model_dump()
                        inv._need(cancelled["id"] == remote.job and cancelled["state"] in wire.TERMINAL,
                                  "runtime_unavailable")
                        remote._send(message, cleanup=True)
                else:
                    message = remote.bridge.reply(op, tool_callback=None, call_admission=None,
                        call_finish=partial(inv.finish_call, self.st, claim, op["step_id"]))
                    remote._send(message, cleanup=True)
            return True
        finally:
            remote.close()
