"""Local free-plan activity with bounded, typed hosted guardrail assessments."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import UUID

import httpx
import yaml
from openaidr_api_client import free_tier
from openaidr_api_client.client import Unavailable
from openaidr_api_client.clients.guardrail import GuardrailClient
from openaidr_api_client.contracts.service_guardrail import GuardrailError

from openaidr.core.policy import ACTIONS, Policy
from openaidr.core.protocol import default_sensor_config
from openaidr.server.guardrail.evidence import event_evidence
from .free_enrollment import prepare
from . import network_proxy
from .usage import identity


SERVICE_FAILURES = {
    "authentication_failed": "authentication_failed", "provider_unavailable": "service_unavailable",
    "provider_rejected": "service_rejected", "invalid_response": "invalid_response",
    "response_too_large": "invalid_response", "connection_failed": "connection_failed",
}
FAILURE_REASONS = frozenset(SERVICE_FAILURES.values()) | {
    "timeout", "capture_disabled", "evidence_truncated", "evidence_unavailable", "evidence_too_large",
    "credits_exhausted", "rate_limited", "unscored", "outcome_unknown", "policy_unavailable", "unknown",
}
RULES_FILE = "guardrail-rules.yaml"
RULE_KEYS = frozenset(("id", "name", "enabled", "action", "reason", "match"))
MATCH_KEYS = frozenset(("kinds", "products", "tool_name", "command_regex", "path_glob", "host_glob"))
RANK = {"allow": 0, "warn": 1, "ask": 2, "deny": 3}


def service_failure_reason(error):
    # The SDK wraps transport errors. Inspect types and status codes, never text.
    cause = error
    for _ in range(5):
        if isinstance(cause, (httpx.TimeoutException, TimeoutError)):
            return "timeout"
        if isinstance(cause, Unavailable):
            reason = {401: "authentication_failed", 403: "authentication_failed",
                      402: "credits_exhausted", 429: "rate_limited"}.get(cause.status_code)
            if reason:
                return reason
        if cause is None:
            break
        cause = cause.__cause__ or cause.__context__
    return SERVICE_FAILURES.get(error.code, "service_unavailable")


class AssessmentUnavailable(Exception):
    def __init__(self, reason, billing=None):
        super().__init__(reason)
        self.reason, self.billing = reason, billing


class RulesSnapshot:
    """One immutable reading of the rules file; a check uses a single snapshot."""

    __slots__ = ("mode", "version", "policy", "error")

    def __init__(self, mode="shadow", version=0, policy=None, error=""):
        self.mode, self.version, self.policy, self.error = mode, version, policy, error

    def decide(self, body):
        """The strongest matching rule decision, allow without a match, None when unavailable."""
        if self.policy is None:
            return None if self.error else {"action": "allow"}
        actions = [{**action, "agent": action.get("agent") or {"product": body["product"]}}
                   for action in body["actions"]]
        results = self.policy.evaluate_many(actions)
        if any(result.get("evaluation_unavailable") for _, result in results):
            return None
        matched = [result for _, result in results if "rule" in result]
        return max(matched, key=lambda result: RANK[result["action"]]) if matched else {"action": "allow"}


class LocalRules:
    """Personal guardrail rules from a YAML file beside the sensor configuration.

    The file maps ``mode`` (``shadow`` or ``enforce``) and ``rules`` in the
    workspace rule format. A missing file means Shadow mode without rules."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.signature = None
        self.snapshot = RulesSnapshot()

    def load(self):
        """Return the current snapshot, re-reading the file only when it changed."""
        with self.lock:
            try:
                stat = self.path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                signature = None
            if signature != self.signature:
                snapshot = RulesSnapshot()
                if signature is not None:
                    try:
                        mode, policy = self._parse(stat.st_size)
                        snapshot = RulesSnapshot(mode, max(0, int(stat.st_mtime)), policy)
                    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError, TypeError) as exc:
                        snapshot = RulesSnapshot(error=str(exc) or "invalid rules file")
                # Replace the whole reading at once; concurrent checks keep the one they hold.
                self.snapshot, self.signature = snapshot, signature
            return self.snapshot

    def _parse(self, size):
        if size > 1 << 20:
            raise ValueError("rules file exceeds 1 MiB")
        data = yaml.safe_load(self.path.read_bytes().decode("utf-8")) or {}
        if not isinstance(data, dict) or not set(data) <= {"mode", "rules"}:
            raise ValueError("rules file must map only mode and rules")
        mode = data.get("mode", "shadow")
        if mode not in ("shadow", "enforce"):
            raise ValueError("mode must be shadow or enforce")
        rules = data.get("rules") or []
        if not isinstance(rules, list) or len(rules) > 500:
            raise ValueError("rules must be a list of at most 500 rules")
        prepared, seen = [], set()
        for index, rule in enumerate(rules, 1):
            if not isinstance(rule, dict) or not set(rule) <= RULE_KEYS:
                raise ValueError(f"rule {index}: unknown fields")
            ident = rule.get("id")
            if not isinstance(ident, str) or not ident.strip() or ident in seen:
                raise ValueError(f"rule {index}: id must be a unique string")
            seen.add(ident)
            name, reason, enabled = rule.get("name", ident), rule.get("reason", ""), rule.get("enabled", True)
            if not isinstance(name, str) or not isinstance(reason, str) or type(enabled) is not bool:
                raise ValueError(f"rule {ident}: name and reason must be strings and enabled a boolean")
            if rule.get("action") not in ACTIONS:
                raise ValueError(f"rule {ident}: action must be one of " + ", ".join(ACTIONS))
            match = rule.get("match")
            if not isinstance(match, dict) or not match or not set(match) <= MATCH_KEYS:
                raise ValueError(f"rule {ident}: match must use " + ", ".join(sorted(MATCH_KEYS)))
            for key, value in match.items():
                if key in ("kinds", "products"):
                    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                        raise ValueError(f"rule {ident}: {key} must be a list of strings")
                elif not isinstance(value, str) or not value:
                    raise ValueError(f"rule {ident}: {key} must be a non-empty string")
            prepared.append({"id": ident, "name": name, "enabled": enabled, "action": rule["action"],
                             "reason": reason, "match": dict(match)})
        policy = Policy({"version": 1, "actions": list(ACTIONS), "rules": prepared})
        if policy.errors:
            raise ValueError("; ".join(policy.errors))
        return mode, policy


def protection(status):
    return dict(schema_version=1, state="active" if status.status == "available" else status.status,
                checked_at=time.time(), guardrail_configured=status.guardrail_configured,
                guardrail_available=status.guardrail_available, credit_status=status.credit_status,
                credits_per_usd=status.credits_per_usd, reset_at=status.reset_at)


class FreeClient:
    """Never send ordinary sensor, telemetry, inventory or alert traffic to the API."""

    def __init__(self, config, *, transport=None):
        if config.get("connection_mode") not in ("free", "api_key"):
            raise ValueError("A verified cloud connection is required")
        self.manual_key = config.get("connection_mode") == "api_key"
        if self.manual_key:
            from .api_key import connection

            remote = connection(config)
        else:
            remote = prepare(config).connection
        self.path = Path(config["data_dir"]) / "free-checks.sqlite3"
        config_path = getattr(config, "path", None)
        self.rules = LocalRules((Path(config_path).parent if config_path else Path(config["data_dir"])) / RULES_FILE)
        self.scope = identity(config)
        # Create privately before SQLite opens it. The parent is already private.
        try:
            os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            pass
        with self.database() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS checks (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, product TEXT NOT NULL,
                hook_event TEXT NOT NULL, status TEXT NOT NULL, decision TEXT,
                billing TEXT, deadline REAL NOT NULL)""")
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='attempts'").fetchone():
                db.execute("CREATE TABLE attempts (id TEXT PRIMARY KEY, billing TEXT)")
                # Preserve identities from an earlier local runtime, conservatively.
                db.execute("INSERT INTO attempts SELECT id,billing FROM checks")
            # Keep the original checks columns so older sensors can still insert.
            db.execute("CREATE TABLE IF NOT EXISTS check_failures (id TEXT PRIMARY KEY, reason TEXT NOT NULL)")
            db.execute("""CREATE TRIGGER IF NOT EXISTS checks_delete_failures AFTER DELETE ON checks
                BEGIN DELETE FROM check_failures WHERE id=OLD.id; END""")
            db.execute("""CREATE TABLE IF NOT EXISTS check_details (
                id TEXT PRIMARY KEY, scope TEXT NOT NULL, evidence TEXT NOT NULL)""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS checks_delete_details AFTER DELETE ON checks
                BEGIN DELETE FROM check_details WHERE id=OLD.id; END""")
            db.execute("""CREATE TABLE IF NOT EXISTS check_policy (
                id TEXT PRIMARY KEY, mode TEXT NOT NULL, returned TEXT NOT NULL,
                rule_id TEXT NOT NULL, rule_name TEXT NOT NULL, reason TEXT NOT NULL)""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS checks_delete_policy AFTER DELETE ON checks
                BEGIN DELETE FROM check_policy WHERE id=OLD.id; END""")
        if transport is None:
            transport = network_proxy.async_transport(config, remote.origin, remote.verify())
        self.remote = GuardrailClient(remote, transport=transport)
        self.credential_generation = None
        self.on_auth_failure = None

    @contextmanager
    def database(self):
        db = sqlite3.connect(self.path, timeout=0.1)
        db.row_factory = sqlite3.Row
        try:
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            db.execute(f"PRAGMA max_page_count={(512 << 20) // page_size}")
            with db:
                yield db
        finally:
            db.close()

    def close(self):
        self.remote.close()

    def post(self, path, body, *, timeout=None):
        if path == "heartbeat":
            # Device/account details and raw activity are deliberately unused.
            if self.manual_key:
                from .api_key import status as key_status

                key_status(self.remote.client)
                # Capabilities prove the connection, not provider access or available credit.
                return dict(tenant_name="API key", cloud_protection=None,
                            disabled=False, config=default_sensor_config())
            status = free_tier.status_sync(self.remote.client)
            return dict(tenant_name="Free plan", cloud_protection=protection(status),
                        disabled=False, config=default_sensor_config())
        if path == "events":
            # Usage projection runs before acknowledgement in the sensor ship loop.
            return dict(accepted=len(body["events"]), duplicates=0, rejected=[])
        if path == "guardrails/summary":
            return self.summary(body["days"])
        if path in ("guardrails/denials", "guardrails/check") and body.get("decision") == "ask":
            return self.ask_checks(path, body)
        # Organization-only capabilities must not reach an unrelated API route.
        request = httpx.Request("POST", "https://local.invalid/" + path)
        raise httpx.HTTPStatusError("Not available on the free plan", request=request,
                                    response=httpx.Response(404, request=request))

    def _assess(self, ident, actions, body, deadline):
        """One hosted assessment; raises AssessmentUnavailable with a safe reason."""
        evidence = [event_evidence({"kind": action["kind"], "body": action}) for action in actions]
        target = dict(evidence[0])
        if len(evidence) > 1:
            target["mapped_actions"] = evidence
        state = dict(target_event=target, latest_prompt=None, prior_events=[],
                     context_limited=True, evidence_status=body["availability"])
        if len(json.dumps(state).encode()) > 24_000:
            raise AssessmentUnavailable("evidence_too_large")
        if deadline - time.monotonic() < .001:
            raise AssessmentUnavailable("timeout")
        with self.database() as db:
            db.execute("INSERT INTO attempts VALUES(?,NULL)", (ident,))
        try:
            result = self.remote.assess(state, request_id=ident, timeout=deadline - time.monotonic())
        except GuardrailError as exc:
            raise AssessmentUnavailable(service_failure_reason(exc), exc.billing) from None
        billing = result["billing"]
        if time.monotonic() >= deadline:
            raise AssessmentUnavailable("timeout", billing)
        if result["status"] != "scored":
            raise AssessmentUnavailable("unscored", billing)
        # Free assessments use fixed risk thresholds.
        decision = "deny" if result["score"] >= 80 else "ask" if result["score"] >= 60 else "allow"
        return decision, billing, state, result

    def check(self, body, deadline):
        ident = str(UUID(body["request_id"]))
        started = datetime.now(timezone.utc)
        local = self.rules.load()
        mode = local.mode
        with self.database() as db:
            # Display history can expire independently of durable dispatch receipts.
            db.execute("DELETE FROM checks WHERE created_at<? AND deadline<?",
                       ((started - timedelta(days=30)).isoformat(), time.time()))
            db.execute("""DELETE FROM checks WHERE id IN (
                SELECT id FROM checks WHERE deadline<? ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET 99999)""",
                       (time.time(),))
            if db.execute("SELECT 1 FROM attempts WHERE id=?", (ident,)).fetchone():
                raise ValueError("Free guardrail request already attempted")
            inserted = db.execute("INSERT OR IGNORE INTO checks VALUES(?,?,?,?,?,?,?,?)",
                (ident, started.isoformat(), body["product"], body["hook_event"], "pending", None,
                 None, time.time() + max(0, deadline - time.monotonic()))).rowcount
        # A lost reply or process restart must not charge for the same check twice.
        if not inserted:
            raise ValueError("Free guardrail request already attempted")
        billing, decision, failure, returned = None, None, "unknown", "allow"
        rule, reason, ruled, state, result = None, "", "allow", None, None
        try:
            actions = body["actions"]
            if not actions or body["availability"] not in ("available", "content_redacted", "unsupported_boundary"):
                failure = {"capture_disabled": "capture_disabled", "content_truncated": "evidence_truncated"}.get(
                    body["availability"], "evidence_unavailable")
                raise ValueError("Guardrail evidence unavailable")
            verdict = local.decide(body)
            if verdict is None:
                failure = "policy_unavailable"
                raise ValueError("Local guardrail rules unavailable")
            ruled, assessed = verdict["action"], None
            # An action a local rule already blocks is not sent for assessment.
            if not (mode == "enforce" and ruled == "deny"):
                try:
                    assessed, billing, state, result = self._assess(ident, actions, body, deadline)
                except AssessmentUnavailable as exc:
                    billing = exc.billing
                    if ruled == "allow":
                        failure = exc.reason
                        raise ValueError("Free guardrail service unavailable") from None
                    # A local rule decision stands when the hosted assessment is unavailable.
            decision = ruled if assessed is None or RANK[ruled] >= RANK[assessed] else assessed
            if decision == ruled and ruled != "allow":
                rule, reason = verdict["rule"], verdict["reason"]
            else:
                reason = "Free guardrail assessment (" + ("Enforce" if mode == "enforce" else "Shadow") + " mode)"
            # Shadow records the decision and lets the action continue, like a workspace.
            returned = decision if mode == "enforce" and body.get("control_supported", True) else "allow"
            return dict(id=ident, request_id=ident, product=body["product"], hook_event=body["hook_event"],
                        status="evaluated", mode=mode, settings_version=0, policy_version=local.version,
                        evaluated_decision=decision, returned_decision=returned, reason=reason,
                        rule_id=rule.get("id", "") if rule else "", rule_name=rule.get("name", "") if rule else "")
        finally:
            with self.database() as db:
                if billing is not None:
                    db.execute("UPDATE attempts SET billing=? WHERE id=?", (json.dumps(billing), ident))
                db.execute("UPDATE checks SET status=?,decision=?,billing=? WHERE id=?",
                    ("evaluated" if decision else "unavailable", decision,
                     json.dumps(billing) if billing is not None else None, ident))
                db.execute("INSERT OR REPLACE INTO check_policy VALUES(?,?,?,?,?,?)",
                    (ident, mode, returned, rule.get("id", "") if rule else "", rule.get("name", "") if rule else "", reason))
                if decision == "ask":
                    # Retain only already captured evidence. Inspection must not change the hook result.
                    try:
                        basis = {"mode": mode, "risk_settings": {"enabled": True, "ask_threshold": 60, "block_threshold": 80}}
                        if ruled != "allow":
                            basis["rule_decision"] = {"action": ruled, "rule": {key: verdict["rule"].get(key, "")
                                                                                 for key in ("id", "name")}}
                        snapshot = json.dumps(dict(actions=actions,
                            assessment_input={"state": state} if state is not None else None, decision_basis=basis,
                            assessment={key: result[key] for key in (
                                "status", "score", "level", "category", "reason", "confidence",
                                "category_confidence", "assessed_at") if key in result} if result is not None else None))
                        if len(snapshot.encode()) <= 64 << 10:
                            db.execute("INSERT INTO check_details VALUES(?,?,?)", (ident, self.scope, snapshot))
                            db.execute("""DELETE FROM check_details WHERE rowid IN (
                                SELECT rowid FROM check_details ORDER BY rowid DESC LIMIT -1 OFFSET 1000)""")
                    except (sqlite3.Error, ValueError, TypeError):
                        pass
                if decision is None:
                    try:
                        db.execute("INSERT OR REPLACE INTO check_failures VALUES(?,?)", (ident, failure))
                    except sqlite3.Error:
                        pass  # Diagnostics must not change the hook result or add retries.

    def ask_checks(self, path, body):
        from openaidr.server.store import Cursor, decode_cursor

        def item(row):
            mode = row["mode"] if row["mode"] in ("shadow", "enforce") else "shadow"
            return {**{key: row[key] for key in ("id", "created_at", "product", "hook_event")},
                    "mode": mode, "returned_decision": row["returned"] if mode == "enforce" and row["returned"] else "allow",
                    "label": None, "note": None, "reviewed_at": None, "review_revision": 0}

        columns = """checks.*,check_policy.mode AS mode,check_policy.returned AS returned,
                     check_policy.reason AS reason FROM checks LEFT JOIN check_policy ON checks.id=check_policy.id"""

        with self.database() as db:
            if path == "guardrails/denials":
                if type(body.get("days")) is not int or body["days"] not in (1, 30):
                    raise ValueError("days must be 1 or 30")
                until = datetime.fromisoformat(body["until"].replace("Z", "+00:00"))
                if until.tzinfo is None:
                    raise ValueError("Invalid check window.")
                until = until.astimezone(timezone.utc)
                since = max(until - timedelta(days=body["days"]), datetime.now(timezone.utc) - timedelta(days=30))
                cursor = decode_cursor(body["cursor"])
                stamp = cursor.time.astimezone(timezone.utc).isoformat() if cursor.time else None
                rows = db.execute(f"""SELECT {columns} WHERE status='evaluated' AND decision='ask'
                    AND checks.created_at>=? AND checks.created_at<? AND (? IS NULL OR (checks.created_at,checks.id)<(?,?))
                    ORDER BY checks.created_at DESC,checks.id DESC LIMIT 21""",
                    (since.isoformat(), until.isoformat(), stamp, stamp, cursor.id)).fetchall()
                last = rows[19] if len(rows) > 20 else None
                return dict(items=[item(row) for row in rows[:20]], review_version=1,
                            next_cursor=Cursor(datetime.fromisoformat(last["created_at"]), last["id"]).encode() if last else "")
            row = db.execute(f"""SELECT {columns} WHERE checks.id=? AND status='evaluated' AND decision='ask'
                AND checks.created_at>=?""", (body["id"], (datetime.now(timezone.utc) - timedelta(days=30)).isoformat())).fetchone()
            if row is None:
                raise ValueError("Ask check not found.")
            saved = db.execute("SELECT evidence FROM check_details WHERE id=? AND scope=?", (row["id"], self.scope)).fetchone()
        snapshot = json.loads(saved["evidence"]) if saved else {}
        summary = item(row)
        reason = row["reason"] or "Free guardrail assessment (Shadow mode)"
        gaps = ["no_prior_context"] if saved else ["policy_snapshot_not_retained"]
        if not snapshot.get("assessment"):
            gaps += ["assessment_input_not_retained", "assessment_not_retained"]
        evidence = dict(assessment_input=snapshot.get("assessment_input"), assessment=snapshot.get("assessment"),
            decision_basis=snapshot.get("decision_basis", {}),
            decision={"evaluated_decision": "ask", "returned_decision": summary["returned_decision"], "reason": reason},
            gaps=gaps)
        return {**summary, "reason": reason, "actions": snapshot.get("actions", []), "evidence": evidence,
                "review_version": 1, "evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()}

    def summary(self, days):
        if type(days) is not int or days not in (1, 30):
            raise ValueError("days must be 1 or 30")
        until = datetime.now(timezone.utc)
        since = (until - timedelta(days=days)).isoformat()
        empty = dict(completed=0, allow=0, warn=0, ask=0, deny=0, unavailable=0, pending=0)
        counts, by_mode, agents, recent = dict(empty), {"shadow": dict(empty), "enforce": dict(empty)}, {}, []
        with self.database() as db:
            rows = db.execute("""SELECT checks.*,check_failures.reason AS failure_reason,
                              check_policy.mode AS mode,check_policy.returned AS returned FROM checks
                              LEFT JOIN check_failures ON checks.id=check_failures.id
                              LEFT JOIN check_policy ON checks.id=check_policy.id
                              WHERE checks.created_at>=? AND checks.created_at<? ORDER BY checks.created_at DESC,checks.id DESC""",
                              (since, until.isoformat()))
            for row in rows:
                status = "unavailable" if row["status"] == "pending" and row["deadline"] <= time.time() else row["status"]
                mode = row["mode"] if row["mode"] in ("shadow", "enforce") else "shadow"
                key = row["decision"] if status == "evaluated" else status
                counts[key] += 1
                by_mode[mode][key] += 1
                counts["completed"] += status == "evaluated"
                by_mode[mode]["completed"] += status == "evaluated"
                agents.setdefault(row["product"], row["created_at"])
                if len(recent) < 20:
                    reason = None
                    if status == "unavailable":
                        reason = "outcome_unknown" if row["status"] == "pending" else (
                            row["failure_reason"] if row["failure_reason"] in FAILURE_REASONS else "unknown")
                    returned = (row["returned"] if mode == "enforce" and row["returned"] else "allow") if status == "evaluated" else None
                    recent.append(dict(id=row["id"], created_at=row["created_at"], product=row["product"],
                        hook_event=row["hook_event"], mode=mode, status=status,
                        evaluated_decision=row["decision"], returned_decision=returned, failure_reason=reason))
        return dict(days=days, since=since, until=until.isoformat(), mode=self.rules.load().mode, summary=counts,
                    by_mode=by_mode, recent=recent,
                    by_agent=[dict(product=name, last_check_at=stamp) for name, stamp in sorted(agents.items())])
