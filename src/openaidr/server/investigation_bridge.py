"""Tenant-owned transaction receipts for the finite investigation mailbox."""

from contextlib import contextmanager
import re
from uuid import uuid4

from psycopg.types.json import Jsonb

from openaidr_api_client.contracts import investigations as wire
from openaidr_api_client.contracts.investigation_runtime import PROMPT_VERSION
from . import session_investigator as inv
from openaidr_api_client.client import Connection


class Bridge:
    def __init__(self, st, claim, connection, profile, *, benchmark_owner_tenant_id=None):
        inv._need(isinstance(connection, Connection), "runtime_unavailable")
        self.st, self.claim, self.connection = st, dict(claim), connection
        self.profile = wire.RuntimeProfile.model_validate(profile).model_dump()
        self.attempt_id = inv._uuid(claim["attempt_id"])
        self.tenant_id = inv._uuid(claim["tenant_id"])
        if benchmark_owner_tenant_id is None:
            inv._need(connection.tenant_id == self.tenant_id, "scope_unavailable")
        else:
            inv._need(benchmark_owner_tenant_id == connection.tenant_id
                      and re.fullmatch(r"detection_benchmark_[0-9a-f]{32}", st.scalar("SELECT current_schema()")),
                      "scope_unavailable")

    def _binding(self, conn):
        rows = self.st.many(
            """SELECT b.* FROM session_investigation_remote_bindings b
               JOIN session_investigation_attempts a ON a.id=b.attempt_id
               WHERE b.attempt_id=$1 AND b.tenant_id=$2 AND a.tenant_id=$2
                 AND a.job_id=$3 AND a.claim_token=$4""",
            self.attempt_id, self.tenant_id, self.claim["job_id"], self.claim["claim_token"], conn=conn,
        )
        inv._need(rows, "claim_expired")
        binding = rows[0]
        inv._need(binding["origin"] == self.connection.origin
                  and binding["owner_tenant_id"] == self.connection.tenant_id
                  and binding["profile"] == self.profile, "runtime_unavailable")
        return binding

    @contextmanager
    def _active(self, *, sources=()):
        # A controlled error rolls back the phase savepoint. Commit any expiry
        # transition made before that savepoint, just as the local fence does.
        error = None
        with self.st.transaction() as conn:
            try:
                with inv._fence(self.st, self.claim, sources=sources, conn=conn) as context:
                    inv._need(context["job"]["tenant_id"] == self.tenant_id, "scope_unavailable")
                    yield context
            except inv.InvestigationStopped as exc:
                error = exc
        if error:
            raise error

    def prepare_binding(self):
        with self._active() as c:
            conn, job, attempt = c["conn"], c["job"], c["attempt"]
            old = self.st.many("SELECT attempt_id FROM session_investigation_remote_bindings WHERE attempt_id=$1",
                               self.attempt_id, conn=conn)
            if old:
                return self._binding(conn)["create_request"]
            inv._need(attempt["plan_sealed_at"] is not None, "incomplete_coverage")
            inv._need(all(attempt["runtime"].get(key) == self.profile[key] for key in
                          ("version", "executable_sha256", "platform", "protocol_version", "prompt_version")),
                      "runtime_unavailable")
            snapshot = self.st.one("SELECT * FROM session_snapshots WHERE id=$1 AND tenant_id=$2",
                                   job["snapshot_id"], self.tenant_id, conn=conn)
            scope = {key: job.get(key) for key in ("tenant_id", "sensor_id", "registration_id", "owner_user_id",
                                                  "session_id", "snapshot_id", "detector_config_version")}
            scope.update(snapshot_revision=snapshot["revision"], snapshot_items=snapshot["item_count"],
                         snapshot_sealed_at=snapshot["sealed_at"].isoformat(),
                         history_window=[item.isoformat() for item in inv.detection_history.bounds(job)])
            value = wire.InvestigationCreate.model_validate(dict(
                protocol_version=self.profile["protocol_version"], attempt_id=self.attempt_id, job_id=job["id"], snapshot_id=job["snapshot_id"],
                detector_config_version=job["detector_config_version"], scope_sha256=wire.digest(scope),
                model=job["configuration"]["model"], runtime_profile_sha256=wire.digest(self.profile),
                deadline_at=min(job["lease_deadline"], attempt["deadline_at"]).isoformat(),
            )).model_dump()
            self.st.execute("""INSERT INTO session_investigation_remote_bindings
                (attempt_id,tenant_id,owner_tenant_id,origin,profile,create_request) VALUES($1,$2,$3,$4,$5,$6)""",
                self.attempt_id, self.tenant_id, self.connection.tenant_id, self.connection.origin,
                Jsonb(self.profile), Jsonb(value), conn=conn)
            return value

    def attach(self, created):
        created = wire.CreatedInvestigation.model_validate(created).model_dump()
        with self._active() as c:
            binding = self._binding(c["conn"])
            request = binding["create_request"]
            inv._need(all(created[key] == request[key] for key in
                          ("attempt_id", "deadline_at", "runtime_profile_sha256")), "invalid_result")
            inv._need(binding["remote_id"] in (None, created["id"]), "request_replayed")
            self.st.execute("UPDATE session_investigation_remote_bindings SET remote_id=$2 WHERE attempt_id=$1",
                            self.attempt_id, created["id"], conn=c["conn"])
            return created["id"]

    def _messages(self, conn, *, kind=None, step_id=None):
        return self.st.many("""SELECT * FROM session_investigation_remote_messages WHERE attempt_id=$1
            AND ($2::text IS NULL OR kind=$2) AND ($3::uuid IS NULL OR step_id=$3) ORDER BY created_at,id""",
            self.attempt_id, kind, step_id, conn=conn)

    def _save(self, conn, value, *, step_id=None, operation=None):
        encoded = wire.canonical(value)
        size = self.st.one("""SELECT count(*) AS count,COALESCE(sum(octet_length(message::text)),0) AS bytes
            FROM session_investigation_remote_messages WHERE attempt_id=$1""", self.attempt_id, conn=conn)
        inv._need(size["count"] < 4096 and size["bytes"] + len(encoded) <= 32 << 20, "budget_exhausted")
        operation = operation or {}
        outcome = value.get("outcome", {})
        response = outcome.get("value")
        read_id = (response.get("read_id") if operation.get("kind") == "read_tool"
                   and isinstance(response, dict) else None)
        # Prompts and read responses already have authoritative immutable tenant
        # records. Retain their message identity/hash, then reconstruct through
        # the scoped controller on replay instead of duplicating raw evidence.
        stored = None if value["type"] == "step" or operation.get("kind") == "read_tool" else Jsonb(value)
        self.st.execute("""INSERT INTO session_investigation_remote_messages
            (id,attempt_id,step_id,kind,message,message_sha256,operation_id,operation_sequence,
             operation_sha256,operation_kind,read_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)""",
            value["message_id"], self.attempt_id, step_id, value["type"], stored, wire.digest(value),
            operation.get("operation_id"), operation.get("sequence"), operation.get("operation_sha256"),
            operation.get("kind"), read_id, conn=conn)
        return value

    def step_message(self, step):
        with self._active() as c:
            inv._need(self._binding(c["conn"])["remote_id"] is not None, "runtime_unavailable")
            stored = inv._step(self.st, c, step["id"])
            inv._need(step["ordinal"] == stored["ordinal"] and step["kind"] == stored["kind"])
            history_allowed = bool(c["job"].get("owner_user_id"))
            inv._need(step["history_allowed"] == history_allowed)
            payload = {"context": step["context"]}
            prior = self._messages(c["conn"], kind="step", step_id=step["id"])
            value = wire.Step.model_validate(dict(type="step", message_id=prior[0]["id"] if prior else str(uuid4()),
                step_id=step["id"], ordinal=step["ordinal"], kind=step["kind"], prompt_version=PROMPT_VERSION,
                **payload, history_allowed=history_allowed)).model_dump()
            inv._need(len(wire.canonical(value)) <= wire.MAX_FRAME, "invalid_request")
            if prior:
                inv._need(prior[0]["message_sha256"] == wire.digest(value), "request_replayed")
                return value
            return self._save(c["conn"], value, step_id=step["id"])

    def _operation(self, conn, operation):
        binding = self._binding(conn)
        inv._need(binding["remote_id"] and operation["deadline_at"] == binding["create_request"]["deadline_at"])
        steps = self._messages(conn, kind="step", step_id=operation["step_id"])
        inv._need(steps and steps[0]["ack_revision"] is not None, "incomplete_coverage")
        if operation["kind"] != "finish_call":
            current = self.st.many("""SELECT id FROM session_investigation_steps WHERE attempt_id=$1
                AND state='prepared' ORDER BY ordinal LIMIT 1""", self.attempt_id, conn=conn)
            inv._need(current and current[0]["id"] == operation["step_id"], "request_replayed")
        else:
            inv._need(self.st.scalar("""SELECT EXISTS(SELECT 1 FROM session_investigation_requests
                WHERE id=$1 AND attempt_id=$2 AND step_id=$3)""",
                inv._uuid(operation["payload"].get("request_id")), self.attempt_id, operation["step_id"], conn=conn),
                "invalid_request")
        rows = self.st.many("""SELECT * FROM session_investigation_remote_messages WHERE attempt_id=$1
             AND (operation_id=$2 OR operation_sequence=$3)""",
             self.attempt_id, operation["operation_id"], operation["sequence"], conn=conn)
        if rows:
            inv._need(len(rows) == 1 and rows[0]["operation_id"] == operation["operation_id"]
                      and rows[0]["operation_sha256"] == operation["operation_sha256"], "request_replayed")
            return rows[0]
        last = self.st.scalar("""SELECT COALESCE(max(operation_sequence),0)
            FROM session_investigation_remote_messages WHERE attempt_id=$1""", self.attempt_id, conn=conn)
        inv._need(operation["sequence"] == last + 1, "request_replayed")
        return None

    def reply(self, operation, *, tool_callback, call_admission, call_finish):
        operation = wire.Operation.model_validate(operation).model_dump()
        inv._need(operation["payload"] is not None and len(wire.canonical(operation["payload"])) <= wire.MAX_FRAME)
        inv._need(operation["operation_sha256"] == wire.digest({key: item for key, item in operation.items()
                                                               if key != "operation_sha256"}))
        kind, payload = operation["kind"], operation["payload"]
        with self.st.transaction() as conn:
            # This preliminary check reads identities only. The authoritative
            # callback retains its authority-before-job lock order below.
            self._operation(conn, operation)
            error, value = None, None
            if kind == "read_tool":
                inv._need(set(payload) == {"call_id", "name", "arguments"})
                try:
                    value = tool_callback(payload["call_id"], payload["name"], payload["arguments"], conn=conn)
                except inv.InvestigationStopped as exc:
                    error = exc
            else:
                try:
                    with inv._fence(self.st, self.claim, conn=conn):
                        pass
                except inv.InvestigationStopped as exc:
                    error = exc
            prior = self._operation(conn, operation)
            if prior:
                if error:
                    raise error  # Never retransmit a previously allowed grant after revocation.
                if kind == "read_tool":
                    value = dict(type="reply", message_id=prior["id"], operation_id=operation["operation_id"],
                                 operation_sha256=operation["operation_sha256"], outcome={"ok": True, "value": value})
                    inv._need(wire.digest(value) == prior["message_sha256"], "scope_unavailable")
                    return value
                return prior["message"]
            if kind != "read_tool" and (error is None or kind == "finish_call"):
                try:
                    value = (call_admission if kind == "admit_call" else call_finish)(payload, conn=conn)
                    if kind == "finish_call":
                        error = None  # Accounting remains permitted after the active fence stops.
                except inv.InvestigationStopped as exc:
                    error = exc
            outcome = {"ok": False, "code": error.code} if error else {"ok": True, "value": value}
            if kind == "read_tool" and not error:
                inv._need(isinstance(value, dict) and len(wire.canonical(value)) <= wire.MAX_READ)
            message = wire.Reply.model_validate(dict(type="reply", message_id=str(uuid4()),
                operation_id=operation["operation_id"], operation_sha256=operation["operation_sha256"],
                outcome=outcome)).model_dump()
            return self._save(conn, message, step_id=operation["step_id"], operation=operation)

    def acknowledge(self, message, ack):
        ack = wire.Acknowledgement.model_validate(ack).model_dump()
        inv._need(ack["message_id"] == message["message_id"]
                  and ack["message_sha256"] == wire.digest(message), "invalid_result")
        with self.st.transaction() as conn:
            self._binding(conn)
            rows = self.st.many("""SELECT * FROM session_investigation_remote_messages
                WHERE id=$1 AND attempt_id=$2 FOR UPDATE""", ack["message_id"], self.attempt_id, conn=conn)
            inv._need(rows and rows[0]["message_sha256"] == ack["message_sha256"]
                      and rows[0]["ack_revision"] in (None, ack["revision"]), "invalid_result")
            self.st.execute("""UPDATE session_investigation_remote_messages SET ack_revision=$3,
                message=CASE WHEN kind='step' OR operation_kind='read_tool' THEN NULL ELSE message END
                WHERE id=$1 AND attempt_id=$2""", ack["message_id"], self.attempt_id, ack["revision"], conn=conn)

    def _verify_result(self, conn, step_id, result):
        result = wire.StepResult.model_validate(result).model_dump()
        inv._need(result["step_id"] == step_id and result["runtime"] == self.profile
                  and isinstance(result["text"], str) and len(result["text"].encode()) <= wire.MAX_RESULT
                  and wire.digest(result["text"]) == result["result_sha256"], "invalid_result")
        prompt = self._messages(conn, kind="step", step_id=step_id)
        inv._need(prompt and prompt[0]["ack_revision"] is not None, "incomplete_coverage")
        parsed = wire.load(result["text"])
        inv._need(inv.valid_result(parsed), "invalid_result")
        delivered = {row["read_id"] for row in self._messages(conn, kind="reply") if row["ack_revision"] is not None}
        inv._need(all(ref["source"] == "target" or ref["read_id"] in delivered
                      for ref in inv._result_references(parsed)), "incomplete_coverage")
        return result["text"]

    def verify_result(self, step_id, result):
        with self._active() as c:
            self._binding(c["conn"])
            return self._verify_result(c["conn"], step_id, result)

    def accept_step(self, step_id, result, complete_callback):
        with self._active() as c:
            self._binding(c["conn"])
            text = self._verify_result(c["conn"], step_id, result)
            prior = self._messages(c["conn"], kind="step_ack", step_id=step_id)
            if prior:
                inv._need(prior[0]["message"]["result_sha256"] == result["result_sha256"], "request_replayed")
                return prior[0]["message"]
            complete_callback(text, conn=c["conn"])
            return self._save(c["conn"], dict(type="step_ack", message_id=str(uuid4()),
                step_id=step_id, result_sha256=result["result_sha256"]), step_id=step_id)

    def finish(self, publish_callback):
        with self.st.transaction() as conn:
            binding = self._binding(conn)
            if binding["publication"] is not None:
                return binding["publication"], self._messages(conn, kind="finish")[0]["message"]
        sources = inv._history_sources(self.st, self.claim)
        with self._active(sources=sources) as c:
            binding = self._binding(c["conn"])
            if binding["publication"] is not None:
                return binding["publication"], self._messages(c["conn"], kind="finish")[0]["message"]
            accepted = self._messages(c["conn"], kind="step_ack")
            inv._need(accepted and all(row["ack_revision"] is not None for row in accepted), "incomplete_coverage")
            last = max(accepted, key=lambda row: self.st.scalar(
                "SELECT ordinal FROM session_investigation_steps WHERE id=$1", row["step_id"], conn=c["conn"]))
            result = publish_callback(conn=c["conn"])
            self.st.execute("UPDATE session_investigation_remote_bindings SET publication=$2 WHERE attempt_id=$1",
                            self.attempt_id, Jsonb(result), conn=c["conn"])
            message = self._save(c["conn"], dict(type="finish", message_id=str(uuid4()),
                last_step_id=last["step_id"], result_sha256=last["message"]["result_sha256"]))
            return result, message

    def recovery(self):
        # Only acknowledgements and publication messages can be recovered without
        # a live fence. Replay other payloads through step_message/reply.
        with self.st.transaction() as conn:
            binding = self._binding(conn)
            messages = self._messages(conn)
            return dict(create_request=binding["create_request"], remote_id=binding["remote_id"],
                profile=binding["profile"], origin=binding["origin"], owner_tenant_id=binding["owner_tenant_id"],
                publication=binding["publication"],
                pending=[{key: row[key] for key in ("id", "kind", "step_id", "operation_id", "message_sha256")}
                         for row in messages if row["ack_revision"] is None],
                messages=[row["message"] for row in messages if row["kind"] in ("step_ack", "finish")
                          and row["ack_revision"] is None])
