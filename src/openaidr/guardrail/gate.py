"""Common held-boundary gate; native execution remains with the caller."""

import asyncio
import copy
from dataclasses import dataclass, field
import hmac
import re
import uuid

from openaidr.core.event import EVIDENCE_GAPS, new_id, validate_event
from openaidr.core.policy import Policy
from openaidr.core.redact import is_secret_key, redact_event, redact_string
from openaidr.core.toolmap import map_tool

from .backend import BackendDenied, BackendError, BackendRejected, BackendUnavailable
from .journal import JournalError, canonical


@dataclass(frozen=True)
class HeldBoundary:
    logical_id: str
    boundary: str
    raw: bytes
    event: dict
    context: dict = field(default_factory=dict)
    delivery_id: str = "primary"
    deliveries: tuple = ("primary",)


@dataclass(frozen=True)
class NativeOutcome:
    outcome: str
    exit_code: int | None = None

    def __post_init__(self):
        if self.outcome not in ("succeeded", "failed", "not_executed", "uncertain"):
            raise ValueError("invalid native outcome")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not -(1 << 31) <= self.exit_code < 1 << 31
        ):
            raise ValueError("invalid native exit code")


@dataclass(frozen=True)
class GateResult:
    status: str
    logical_id: str
    release_id: str | None = None
    reason: str = ""
    warned: bool = False


_KINDS = {
    "prompt": {"prompt"},
    "tool_call": {"tool.call", "command", "file.read", "file.write", "network"},
    "tool_output": {"tool.result"},
    "assistant_response": {"response"},
}
_IDENTITY = (
    "version",
    "logical_id",
    "observation_id",
    "stream_id",
    "sequence",
    "part",
    "gaps",
)


def _gap(event, code):
    event["evidence"]["gaps"] = sorted(set(event["evidence"]["gaps"]) | {code})


def _capture_event(event, capture, binding):
    if validate_event(event):
        raise JournalError("invalid_boundary")
    if (
        event["agent"]["product"] != binding["product"]
        or event.get("session", {}).get("id") != binding["session_id"]
    ):
        raise JournalError("foreign_evidence")
    if event["session"].get("registration_id") != binding["registration_id"]:
        raise JournalError("foreign_evidence")
    # Reject malformed policy inputs before evaluating cached deterministic rules.
    for key, fields in (
        ("command", ("text", "cwd")),
        ("tool", ("name", "call_id")),
        ("file", ("path",)),
        ("network", ("host", "url")),
    ):
        value = event.get(key, {})
        if not isinstance(value, dict) or any(
            name in value and not isinstance(value[name], str) for name in fields
        ):
            raise JournalError("invalid_boundary")
    canonical(event)  # Validate finite JSON before traversing/copying it.
    result = {name: copy.deepcopy(event[name]) for name in ("id", "time", "kind")}
    result["id"] = str(uuid.UUID(result["id"]))
    for name, fields in (
        ("agent", ("product", "version", "account")),
        ("host", ("hostname", "os", "arch", "user", "kind")),
        ("session", ("id", "registration_id")),
        ("tool", ("name", "call_id", "input", "output")),
        ("command", ("text", "cwd")),
        ("file", ("path",)),
        ("network", ("host", "url", "port")),
    ):
        if name in event:
            result[name] = {
                key: copy.deepcopy(event[name][key])
                for key in fields
                if key in event[name]
            }
    result["evidence"] = {
        key: copy.deepcopy(event["evidence"][key]) for key in _IDENTITY
    }
    if result["kind"] in ("prompt", "response") and "text" in event:
        result["text"] = event["text"]
    if "raw" in event:
        permitted = (
            capture.get("prompt_text")
            if result["kind"] == "prompt"
            else capture.get("response_text")
            if result["kind"] == "response"
            else capture.get("tool_output")
            if result["kind"] == "tool.result"
            else capture.get("tool_input")
        )
        if permitted:
            result["raw"] = copy.deepcopy(event["raw"])
        else:
            _gap(result, "capture_disabled")
    if not capture.get("tool_input"):
        for key in ("command", "file", "network"):
            if result.pop(key, None) is not None:
                _gap(result, "capture_disabled")
        if result["kind"] in ("command", "file.read", "file.write", "network"):
            # The original native action still reaches local policy. This
            # content-suppressed observation must remain a valid event.
            result["kind"] = "tool.call"
            result.setdefault("tool", {}).setdefault("name", event["kind"])
    tool = result.get("tool", {})
    if "output" in tool and not isinstance(tool["output"], str):
        tool["output"] = canonical(tool["output"]).decode()
    redact_event(result, capture)
    if capture.get("redact"):
        changed = False

        def redact(value):
            nonlocal changed
            if isinstance(value, dict):
                clean = {}
                for key, item in value.items():
                    if is_secret_key(key):
                        clean[key] = "[REDACTED]"
                        changed |= item != "[REDACTED]"
                    else:
                        clean[key] = redact(item)
                return clean
            if isinstance(value, list):
                return [redact(item) for item in value]
            if isinstance(value, str):
                clean, rules = redact_string(value)
                changed |= bool(rules)
                return clean
            return value

        evidence = copy.deepcopy(result["evidence"])
        result = redact(result)
        result["evidence"] = evidence
        if changed:
            _gap(result, "content_redacted")
    return result


def _observation(event, binding):
    result = copy.deepcopy(event)
    namespace = uuid.UUID(binding["registration_id"] or binding["epoch_id"])
    result["id"] = str(uuid.uuid5(namespace, event["id"] + ":full"))
    result["evidence"]["observation_id"] = result["id"]
    result["source"] = {
        "type": "managed_full_observation",
        "target_event_id": event["id"],
    }
    return result


def _inline_event(event):
    result = copy.deepcopy(event)
    if len(canonical(result)) <= 8 << 10:
        return result
    result.pop("raw", None)
    _gap(result, "content_truncated")
    limit = 4096
    while len(canonical(result)) > 8 << 10:
        for obj, key in (
            (result, "text"),
            (result.get("command", {}), "text"),
            (result.get("command", {}), "cwd"),
            (result.get("file", {}), "path"),
            (result.get("network", {}), "host"),
            (result.get("network", {}), "url"),
            (result.get("tool", {}), "input"),
            (result.get("tool", {}), "output"),
        ):
            if key not in obj:
                continue
            value = obj[key]
            encoded = value.encode() if isinstance(value, str) else canonical(value)
            if len(encoded) > limit:
                prefix = encoded[:limit].decode("utf-8", errors="ignore")
                obj[key] = (
                    prefix
                    if isinstance(value, str)
                    else {"_truncated": True, "prefix": prefix}
                )
        if limit <= 128 and len(canonical(result)) > 8 << 10:
            raise JournalError("inline_metadata_too_large")
        limit //= 2
    return result


def _captured(held, capture, binding):
    full_target = _capture_event(held.event, capture, binding)
    if (
        held.boundary not in _KINDS
        or full_target["kind"] not in _KINDS[held.boundary]
        or full_target["evidence"]["logical_id"] != held.logical_id
    ):
        raise JournalError("invalid_boundary")
    raw = held.context
    if not isinstance(raw, dict) or set(raw) - {
        "prior_events",
        "latest_prompt",
        "matched_tool_call",
        "gaps",
    }:
        raise JournalError("invalid_context")
    prior = raw.get("prior_events", [])
    if not isinstance(prior, list) or len(prior) > 12:
        raise JournalError("invalid_context")
    gaps = raw.get("gaps", [])
    if (
        not isinstance(gaps, list)
        or len(gaps) > 32
        or any(not isinstance(code, str) or code not in EVIDENCE_GAPS for code in gaps)
    ):
        raise JournalError("invalid_context")
    target = _inline_event(full_target)
    observations = []
    if target != full_target:
        observations.append(_observation(full_target, binding))

    # Context is conversation evidence too. Keep its full permitted view even
    # if the bounded assessment later drops an older item.
    def capture_context(event):
        full = _capture_event(event, capture, binding)
        observations.append(_observation(full, binding))
        return _inline_event(full)

    context = {
        "prior_events": [capture_context(event) for event in prior],
        "gaps": list(gaps),
    }
    for name in ("latest_prompt", "matched_tool_call"):
        context[name] = (
            capture_context(raw[name]) if raw.get(name) is not None else None
        )
    # Keep the target, matching tool call and latest prompt. Drop only old
    # context or optional raw payloads to meet the receiver's bounded envelope.
    while (
        len(canonical({"target": target, "context": context})) > 60 << 10
        and context["prior_events"]
    ):
        context["prior_events"].pop(0)
        context["gaps"] = sorted(set(context["gaps"]) | {"content_truncated"})
    if len(canonical({"target": target, "context": context})) > 60 << 10:
        for event in (target, context["latest_prompt"], context["matched_tool_call"]):
            if event is not None and event.pop("raw", None) is not None:
                _gap(event, "content_truncated")
    if len(canonical({"target": target, "context": context})) > 60 << 10:
        raise JournalError("captured_boundary_too_large")
    return target, context, observations


class JournalDelivery:
    """Recover retained records without checking policy or releasing native work."""

    def __init__(self, journal, backend, *, on_denied=None):
        self.journal, self.backend = journal, backend
        self.on_denied = on_denied
        self.flush_lock = asyncio.Lock()

    def _same_enrollment(self):
        return all(
            self.backend.identity[key] == self.journal.binding[key]
            for key in ("server_url", "tenant_id", "sensor_id")
        )

    def _bound(self, value, action, *, check_id=None):
        if (
            not isinstance(value, dict)
            or any(
                value.get(key) != expected
                for key, expected in (
                    ("registration_id", self.journal.binding["registration_id"]),
                    ("event_id", action["event_id"]),
                    ("logical_id", action["logical_id"]),
                    ("action_commitment", action["commitment"]),
                )
            )
            or check_id is not None
            and value.get("check_id") != check_id
        ):
            raise BackendRejected("invalid_backend_binding")

    async def _registration_status(self, *, include_policy=False):
        generation = self.journal.authorization()["generation"]
        try:
            value = await self.backend.status(
                self.journal.binding["registration_id"], include_policy=include_policy
            )
        except BackendRejected as exc:
            if exc.status == 404:
                raise BackendDenied("registration_unavailable", 404) from None
            raise
        if any(
            value.get(key) != expected
            for key, expected in (
                ("id", self.journal.binding["registration_id"]),
                ("product", self.journal.binding["product"]),
                ("external_id", self.journal.binding["session_id"]),
                ("delivery_epoch", self.journal.binding["epoch_id"]),
                ("assessment_mode", "inline"),
                ("delivery_protocol", 1),
                ("status", "verified"),
            )
        ):
            raise BackendDenied("registration_unavailable")
        return value, generation

    async def _status(self):
        value, generation = await self._registration_status()
        if not self.journal.recover_authorization(generation):
            raise BackendDenied("backend_denied")
        return value

    async def flush(self):
        if (
            not self._same_enrollment()
            or self.journal.binding["registration_id"] is None
        ):
            return False
        async with self.flush_lock:
            try:
                if self.journal.authorization()["denied"]:
                    await self._status()
                while rows := self.journal.pending():
                    # Each receipt stays bound to its original sequence even
                    # if transport batch sizes change between retries.
                    for row in rows:
                        if row["event"] is not None:
                            await self.backend.events([row["event"]])
                        operation = row["operation"]
                        if operation is not None:
                            action = self.journal.action(row["logical_id"])
                            if operation["kind"] == "reconcile_consume":
                                release = await self.backend.consume(
                                    operation["check_id"],
                                    operation["request_id"],
                                    operation["commitment"],
                                )
                                self._bound(
                                    release, action, check_id=operation["check_id"]
                                )
                                operation = {
                                    "kind": "outcome",
                                    "release_id": release["id"],
                                    "outcome": operation["outcome"],
                                    "exit_code": operation["exit_code"],
                                }
                                self.journal.update(
                                    action["logical_id"],
                                    release_id=release["id"],
                                    consume_uncertain=0,
                                )
                            reported = await self.backend.outcome(
                                operation["release_id"],
                                operation["outcome"],
                                exit_code=operation["exit_code"],
                            )
                            self._bound(reported, action, check_id=action["check_id"])
                            self.journal.resolve_operation(
                                row["sequence"],
                                {
                                    "release_id": reported["id"],
                                    "outcome_audit_id": reported["outcome_audit_id"],
                                },
                            )
                    ready = [
                        row
                        for row in self.journal.pending()
                        if row["sequence"] <= rows[-1]["sequence"]
                    ]
                    records, size = [], 0
                    for row in ready:
                        count = len(canonical(row["receipt"]))
                        if records and size + count > 60 << 10:
                            break
                        size += count
                        records.append(row["receipt"])
                    await self.backend.delivery(
                        self.journal.binding["registration_id"],
                        self.journal.binding["epoch_id"],
                        records,
                    )
                    self.journal.acknowledge([row["sequence"] for row in records])
                closing = self.journal.closing()
                if closing:
                    await self.backend.close_session(
                        self.journal.binding["registration_id"], closing
                    )
                return True
            except BackendDenied:
                self.journal.deny_authorization()
                if self.on_denied is not None:
                    await self.on_denied()
                return False
            except BackendError:
                return False

    async def close_session(self, *, reason, boundaries, gaps=()):
        self.journal.closing(
            {
                "reason": reason,
                "boundaries": boundaries,
                "gaps": gaps,
            }
        )
        return await self.flush()


class Gate(JournalDelivery):
    def __init__(self, journal, backend, policy, capture, *, poll_interval=0.25,
                 on_approval=None, on_policy=None, on_denied=None):
        super().__init__(journal, backend, on_denied=on_denied)
        self.policy = policy
        self.capture = copy.deepcopy(capture)
        if not 0 < poll_interval <= 60:
            raise ValueError("invalid approval polling interval")
        self.poll_interval = poll_interval
        self.on_approval = on_approval
        self.on_policy = on_policy
        self.locks = {}
        self.grants = {}
        self._cached_policy()

    @staticmethod
    def _validated_policy(snapshot):
        try:
            if (
                not isinstance(snapshot, dict)
                or type(snapshot.get("version")) is not int
                or snapshot["version"] < 0
                or not isinstance(snapshot.get("rules"), list)
            ):
                raise ValueError
            canonical(snapshot)
            policy = Policy(policy=snapshot)
            if not policy.current or policy.errors:
                raise ValueError
            return policy
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise BackendRejected("invalid_backend_response") from None

    def _cached_policy(self):
        snapshot = self.journal.learned_policy()
        with self.policy.lock:
            if snapshot is not None and snapshot["version"] >= self.policy.version:
                learned = self._validated_policy(snapshot)
                if learned.policy != self.policy.policy:
                    self.policy.set(learned.policy)
        return self.policy

    def _cached_action(self, held):
        policy = self._cached_policy()
        with policy.lock:
            return self._policy_action(policy, held), policy.version

    @staticmethod
    def _policy_action(policy, held):
        events = [held.event]
        tool = held.event.get("tool", {})
        if held.boundary == "tool_call" and tool.get("name"):
            value = tool.get("input")
            base = {key: item for key, item in held.event.items() if key not in ("command", "file", "network")}
            events.extend({**base, **item} for item in map_tool(
                held.event["agent"]["product"], tool["name"], value,
                value if isinstance(value, str) else "",
            ))
        rank = {"allow": 0, "warn": 1, "ask": 2, "deny": 3}
        actions = [decision.get("action") for _, decision in policy.evaluate_many(events)]
        if any(action not in rank for action in actions):
            raise BackendRejected("invalid_backend_response")
        return max(actions, key=rank.__getitem__)

    def _dispatch_fence(self, held):
        if self.journal.authorization()["denied"]:
            raise BackendDenied("backend_denied")
        action = self.journal.action(held.logical_id)
        local_action, version = self._cached_action(held)
        if action["restriction"] in ("block", "rejected", "denied"):
            raise BackendRejected("action_rejected")
        context_policy = self.journal.context_policy()
        if context_policy and context_policy["required"] and (
            not action["release_id"] or context_policy["version"] != action["settings_version"]
        ):
            raise BackendRejected("context_changed")
        if (
            action["consume_id"]
            and action["policy_version"] is not None
            and action["policy_version"] != version
        ):
            raise BackendRejected("policy_changed")
        if local_action == "deny" or action["local_action"] == "deny":
            raise BackendRejected("action_blocked")
        if (local_action == "ask" or action["local_action"] == "ask") and not (
            action["local_action"] == "ask"
            and action["consume_id"]
            and held.logical_id in self.grants
        ):
            raise BackendRejected("approval_pending")
        if local_action == "warn":
            self.journal.update(held.logical_id, warned=1)

    def _result(self, logical_id, delivery_id):
        action = self.journal.action(logical_id)
        delivery = self.journal.delivery(logical_id, delivery_id)
        outcome, reason = delivery["outcome"], delivery["reason"]
        status = (
            "blocked"
            if outcome == "not_executed"
            and reason in ("blocked", "rejected", "expired")
            else "cancelled"
            if outcome == "not_executed"
            else outcome or "uncertain"
        )
        return GateResult(
            status, logical_id, action["release_id"], reason, bool(action["warned"])
        )

    def _finish(self, held, outcome, reason, exit_code=None):
        self.journal.finish_delivery(
            held.logical_id, held.delivery_id, outcome, exit_code, reason
        )
        return self._result(held.logical_id, held.delivery_id)

    async def _status(self):
        value, generation = await self._registration_status(include_policy=True)
        if any(
            type(value.get(key)) is not int or value[key] < 0
            for key in ("settings_version", "policy_version")
        ):
            raise BackendRejected("invalid_backend_response")
        context_policy = value.get("context_policy")
        if context_policy is not None:
            if (
                not isinstance(context_policy, dict)
                or set(context_policy) != {"version", "required", "failure_action"}
                or type(context_policy["version"]) is not int
                or context_policy["version"] != value["settings_version"]
                or type(context_policy["required"]) is not bool
                or context_policy["failure_action"] not in ("ask", "block")
            ):
                raise BackendRejected("invalid_backend_response")
            self.journal.learn_context_policy(context_policy)
        known_context = self.journal.context_policy()
        if "context_version" in value and (type(value["context_version"]) is not int or value["context_version"] != 1):
            raise BackendRejected("invalid_backend_response")
        if known_context and (
            known_context["version"] > value["settings_version"]
            or (known_context["required"] and (context_policy is None or value.get("context_version") != 1))
        ):
            raise BackendRejected("policy_changed")
        snapshot = value.get("policy")
        if snapshot is None:
            policy = self._cached_policy()
            if policy.version != value["policy_version"]:
                raise BackendRejected("policy_changed")
        else:
            policy = self._validated_policy(snapshot)
            if policy.version != value["policy_version"]:
                raise BackendRejected("invalid_backend_response")
            self.journal.learn_policy(policy.policy)
            policy = self._cached_policy()
            if policy.version != value["policy_version"]:
                raise BackendRejected("policy_changed")
            if self.on_policy is not None:
                await self.on_policy(policy.policy)
        if not self.journal.recover_authorization(generation):
            raise BackendDenied("backend_denied")
        return value, policy

    async def _authorize(self, held):
        for attempt in range(3):
            try:
                return await self._authorize_once(held)
            except BackendRejected as exc:
                if exc.code != "context_changed" or attempt == 2:
                    raise
                action = self.journal.action(held.logical_id)
                if action["release_id"] or action["consume_uncertain"] or action["outcome"] is not None:
                    raise JournalError("action_not_replayable") from None
                # A definitive context_changed response grants no execution.
                # Preserve the original evidence, commitment, and restrictions.
                self.journal.update(
                    held.logical_id, request_id=new_id(), check_id=None,
                    approval_id=None, consume_id=None, state="checking",
                )

    async def _authorize_once(self, held):
        action = self.journal.action(held.logical_id)
        if action["restriction"] in ("block", "rejected", "denied"):
            raise BackendRejected("action_rejected")
        if held.logical_id in self.grants:
            # Only an in-memory grant may authorize another declared consumer.
            # A receipt restored from disk never becomes executable permission.
            if self.grants[held.logical_id] != action["commitment"]:
                raise JournalError("payload_changed")
            local_action, version = self._cached_action(held)
            if (
                action["policy_version"] is not None
                and version != action["policy_version"]
            ):
                raise BackendRejected("policy_changed")
            if local_action == "deny" or (
                local_action == "ask" and action["local_action"] != "ask"
            ):
                raise BackendRejected("action_blocked")
            if local_action == "warn":
                self.journal.update(held.logical_id, warned=1)
            if self.journal.binding["registration_id"] is None:
                return
            try:
                status, _ = await self._status()
            except BackendUnavailable:
                return
            if any(
                status[key] != action[key]
                for key in ("settings_version", "policy_version")
            ):
                raise BackendRejected("policy_changed")
            return
        if action["outcome"] is not None or action["consume_id"]:
            raise JournalError("action_not_replayable")
        if self.journal.binding["registration_id"] is None:
            raise BackendUnavailable("backend_unavailable")
        status, policy = await self._status()
        local_action = self._policy_action(policy, held)
        if local_action not in ("allow", "warn", "ask", "deny"):
            raise BackendRejected("invalid_backend_response")
        action = self.journal.update(
            held.logical_id,
            state="checking",
            local_action=local_action,
            warned=int(bool(action["warned"]) or local_action == "warn"),
            settings_version=status["settings_version"],
            policy_version=status["policy_version"],
        )
        while True:
            payload = {
                "request_id": action["request_id"],
                "registration_id": self.journal.binding["registration_id"],
                "settings_version": action["settings_version"],
                "policy_version": action["policy_version"],
                "action_commitment": action["commitment"],
                "target": action["target"],
                "context": action["context"],
            }
            if status.get("context_version") == 1:
                payload["context_version"] = 1
            if action["local_action"] in ("ask", "deny"):
                payload["policy_floor"] = (
                    "block" if action["local_action"] == "deny" else "ask"
                )
            checked = await self.backend.check(payload)
            self._bound(checked, action)
            action = self.journal.update(
                held.logical_id, check_id=str(uuid.UUID(checked["id"]))
            )
            if checked.get("status") != "pending":
                break
            await asyncio.sleep(self.poll_interval)
        decision = checked.get("decision", {}).get("action")
        if decision not in ("allow", "ask", "block"):
            raise BackendRejected("invalid_backend_response")
        if checked.get("decision", {}).get("warnings"):
            self.journal.update(held.logical_id, warned=1)
        if action["local_action"] == "deny" or decision == "block":
            self.journal.update(held.logical_id, restriction="block")
            raise BackendRejected("action_blocked")
        if action["local_action"] == "ask" and decision != "ask":
            raise BackendRejected("approval_pending")
        if decision == "ask":
            self.journal.update(held.logical_id, restriction="ask")
            approval = checked.get("approval", {})
            if approval.get("availability") != "available":
                raise BackendRejected("approvals_disabled")
            ident = str(uuid.UUID(approval["id"]))
            action = self.journal.update(
                held.logical_id, state="waiting", approval_id=ident
            )
            if self.on_approval is not None:
                await self.on_approval(ident, held.boundary)
            while True:
                approval = await self.backend.approval_status(ident)
                if any(
                    approval.get(key) != expected
                    for key, expected in (
                        ("id", ident),
                        ("registration_id", self.journal.binding["registration_id"]),
                        ("event_id", action["event_id"]),
                        ("logical_id", held.logical_id),
                    )
                ):
                    raise BackendRejected("invalid_backend_binding")
                if (
                    approval.get("status") == "approved"
                    and approval.get("valid") is True
                ):
                    break
                if approval.get("status") != "pending":
                    if approval.get("reason_code") == "context_changed":
                        raise BackendRejected("context_changed")
                    if approval.get("status") in ("rejected", "revoked"):
                        self.journal.update(held.logical_id, restriction="rejected")
                    raise BackendRejected(
                        "approval_expired"
                        if approval.get("status") == "expired"
                        else "action_rejected"
                    )
                await asyncio.sleep(self.poll_interval)
        action = self.journal.update(
            held.logical_id, state="consuming", consume_id=new_id(), consume_uncertain=1
        )
        try:
            release = await self.backend.consume(
                action["check_id"], action["consume_id"], action["commitment"]
            )
        except (BackendDenied, BackendRejected):
            self.journal.update(held.logical_id, consume_uncertain=0)
            raise
        self._bound(release, action, check_id=action["check_id"])
        if release.get("granted") is not True or release.get("replayed") is not False:
            raise JournalError("action_not_replayable")
        self.journal.update(
            held.logical_id,
            state="authorized",
            release_id=str(uuid.UUID(release["id"])),
            consume_uncertain=0,
        )
        self.grants[held.logical_id] = action["commitment"]

    async def gate(self, held, release):
        if not self._same_enrollment():
            return GateResult("blocked", held.logical_id, reason="enrollment_changed")
        prepared = False
        try:
            if (
                not isinstance(held.raw, bytes)
                or not held.deliveries
                or len(held.deliveries) > 4
                or len(set(held.deliveries)) != len(held.deliveries)
                or held.delivery_id not in held.deliveries
                or any(
                    not isinstance(name, str)
                    or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name)
                    for name in held.deliveries
                )
            ):
                raise JournalError("invalid_delivery")
            target, context, observations = _captured(
                held, self.capture, self.journal.binding
            )
            local_action, _ = self._cached_action(held)
            commitment = self.journal.commitment(
                held.logical_id,
                held.boundary,
                held.raw,
                held.deliveries,
                {"event": held.event, "context": held.context},
            )
            action = self.journal.prepare(
                held.logical_id,
                commitment,
                target,
                context,
                local_action,
                held.deliveries,
                observations,
            )
            prepared = True
            delivery = self.journal.delivery(held.logical_id, held.delivery_id)
            if delivery["outcome"] is not None or delivery["state"] != "waiting":
                return self._result(held.logical_id, held.delivery_id)
            async with self.locks.setdefault(held.logical_id, asyncio.Lock()):
                delivery = self.journal.delivery(held.logical_id, held.delivery_id)
                if delivery["outcome"] is not None or delivery["state"] != "waiting":
                    return self._result(held.logical_id, held.delivery_id)
                try:
                    await self._authorize(held)
                except BackendUnavailable:
                    action = self.journal.action(held.logical_id)
                    if self.journal.authorization()["denied"]:
                        raise BackendDenied("backend_denied")
                    if action["consume_id"]:
                        return self._finish(held, "uncertain", "consume_uncertain")
                    latest, _ = self._cached_action(held)
                    if (
                        action["restriction"]
                        or action["state"] == "waiting"
                        or action["local_action"] in ("deny", "ask")
                        or latest in ("deny", "ask")
                        or (self.journal.context_policy() or {}).get("required")
                    ):
                        self.journal.update(held.logical_id, restriction="rejected")
                        return self._finish(held, "not_executed", "blocked")
                    self.journal.add_gap(held.logical_id, "backend_unavailable")
                    self.journal.update(
                        held.logical_id,
                        state="authorized",
                        reason="backend_unavailable",
                    )
                    self.grants[held.logical_id] = commitment
                # Other actions or flush may have learned a denial or policy
                # while this action awaited status, assessment, or consumption.
                self._dispatch_fence(held)
                if not hmac.compare_digest(
                    commitment,
                    self.journal.commitment(
                        held.logical_id,
                        held.boundary,
                        held.raw,
                        held.deliveries,
                        {"event": held.event, "context": held.context},
                    ),
                ):
                    raise JournalError("payload_changed")
                self.journal.dispatch_intent(held.logical_id, held.delivery_id)
            try:
                result = await release(held.raw)
                if not isinstance(result, NativeOutcome):
                    raise ValueError("invalid callback result")
            except asyncio.CancelledError:
                raise
            except Exception:
                return self._finish(held, "uncertain", "callback_uncertain")
            action = self.journal.action(held.logical_id)
            reason = (
                "backend_unavailable"
                if action["reason"] == "backend_unavailable"
                else "cancelled"
                if result.outcome == "not_executed"
                else ""
            )
            return self._finish(held, result.outcome, reason, result.exit_code)
        except asyncio.CancelledError:
            if prepared:
                action = self.journal.action(held.logical_id)
                delivery = self.journal.delivery(held.logical_id, held.delivery_id)
                uncertain = (
                    delivery["state"] == "dispatching" or action["consume_uncertain"]
                )
                self._finish(
                    held, "uncertain" if uncertain else "not_executed", "cancelled"
                )
            raise
        except (BackendDenied, BackendRejected) as exc:
            if isinstance(exc, BackendDenied):
                self.journal.deny_authorization()
                if self.on_denied is not None:
                    await self.on_denied()
            if prepared:
                self.journal.update(
                    held.logical_id,
                    restriction="denied"
                    if isinstance(exc, BackendDenied)
                    else "rejected",
                )
                result = self._finish(
                    held,
                    "not_executed",
                    "expired" if exc.code == "approval_expired" else "blocked",
                )
                return GateResult(
                    "blocked",
                    held.logical_id,
                    result.release_id,
                    exc.code,
                    result.warned,
                )
            return GateResult("blocked", held.logical_id, reason=exc.code)
        except (JournalError, ValueError, TypeError, KeyError, RecursionError) as exc:
            reason = str(exc) if isinstance(exc, JournalError) else "invalid_boundary"
            if prepared and reason == "action_not_replayable":
                return self._finish(held, "uncertain", "consume_uncertain")
            if prepared and reason == "payload_changed":
                # The exact release was consumed, but this callback has not
                # been dispatched. Report that known outcome before closing.
                self.journal.update(held.logical_id, restriction="rejected")
                result = self._finish(held, "not_executed", "blocked")
                return GateResult(
                    "blocked", held.logical_id, result.release_id, reason, result.warned
                )
            return GateResult("blocked", held.logical_id, reason=reason)

    async def observe(self, event, gaps=()):
        if not self._same_enrollment():
            raise JournalError("enrollment_changed")
        self.journal.observe(_capture_event(event, self.capture, self.journal.binding), gaps)

    async def settle(self):
        # The caller has stopped native producers and joined active gate calls.
        # Seal even consumers whose callback was never invoked.
        self.grants.clear()
        self.journal.settle()
