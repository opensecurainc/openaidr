import copy
import re
import threading

from openaidr_common.policy import compile_glob as compile_glob, compile_rules

from . import _policy_worker




# Rule actions this matcher applies; the server adapts the policy to them.
ACTIONS = ("allow", "ask", "deny", "warn")


# Positions of the ask rules stored as denies, kept outside the rules so no
# field a caller sets on a rule can turn a deny into an ask.
STORED_ASK = "_stored_ask_rules"


class Policy:
    def __init__(self, policy=None, *, path_windows=None, path_home=None):
        self.lock = threading.RLock()
        self.path_windows, self.path_home = path_windows, path_home
        Policy.set(self, policy or {})

    _compile_rules = staticmethod(compile_rules)

    def _set_compiled(self, policy, rules, errors):
        self.policy, self.rules, self.errors = copy.deepcopy(policy), rules, errors
        self.policy.pop(STORED_ASK, None)

    def set(self, policy):
        rules, errors = self._compile_rules(
            policy, path_windows=self.path_windows, path_home=self.path_home,
        )
        with self.lock:
            self._set_compiled(policy, rules, errors)

    @property
    def version(self):
        return self.policy.get("version", 0)

    @property
    def current(self):
        """False when the server prepared this policy for fewer actions than
        this sensor applies, for example before an upgrade."""
        return set(ACTIONS) <= set(self.policy.get("actions") or ())

    def evaluate(self, event):
        return self.evaluate_many([event])[0][1]

    def evaluate_many(self, events):
        """Evaluate one action set under one budget; a deny ends the set."""
        events = list(events)
        if not events:
            return []
        with self.lock:
            rules = self.rules
        try:
            applicable = next((event for event in events
                               if any(_could_apply(rule, event) for rule, _ in rules)), None)
        except (AttributeError, TypeError):
            # Malformed cached selectors still fail inside the worker, rather
            # than escaping the caller's evaluation-unavailable handling.
            applicable = events[0]
        if applicable is None:
            return [(event, {"action": "allow"}) for event in events]
        # Only matching inputs cross the private worker boundary, not tool
        # output, credentials in unrelated fields, or full captured evidence.
        targets = []
        for event in events:
            target = {"kind": event.get("kind")}
            for key, field in (("agent", "product"), ("tool", "name"),
                               ("command", "text"), ("file", "path"), ("network", "host")):
                if key in event:
                    target[key] = {field: event[key].get(field, "")} if event[key] else {}
            targets.append(target)
        try:
            results = _policy_worker.evaluate(rules, targets)
        except _policy_worker.EvaluationUnavailable as exc:
            return [(applicable, _unavailable(str(exc)))]
        decisions = []
        for event_index, rule_index, error in results:
            if error:
                decision = _unavailable(error)
            elif rule_index is None:
                decision = {"action": "allow"}
            else:
                rule = rules[rule_index][0]
                action = rule.get("action", "allow")
                reason = rule.get("reason")
                decision = {
                    "action": action,
                    "rule": rule,
                    # A malformed reason must not fail the check open.
                    "reason": (reason if isinstance(reason, str) else "")
                    or (
                        "Blocked by OpenAIDR policy rule "
                        if action == "deny"
                        else "Matched OpenAIDR policy rule "
                    )
                    + rule.get("name", ""),
                }
            decisions.append((events[event_index], decision))
        return decisions


def _unavailable(detail):
    return {
        "evaluation_unavailable": True,
        "evaluation_detail": detail,
        "action": "deny",
        "rule": {"name": "Policy evaluation unavailable"},
        "reason": "Policy evaluation could not complete (" + detail + "). "
        "The action was blocked without claiming a policy rule matched.",
    }


def _could_apply(rule, event):
    """Cheap selectors only; all pattern matching stays in the worker."""
    if not rule.get("enabled"):
        return False
    m = rule.get("match", {})
    if m.get("kinds") and event.get("kind") not in m["kinds"]:
        return False
    if m.get("products") and event.get("agent", {}).get("product") not in m["products"]:
        return False
    tool = m.get("tool_name", "")
    name = event.get("tool", {}).get("name", "")
    if tool and not (name.startswith(tool[:-1]) if tool.endswith("*") else name == tool):
        return False
    if m.get("command_regex") and "command" not in event:
        return False
    if m.get("path_glob") and "file" not in event:
        return False
    if m.get("host_glob") and not (event.get("network") or {}).get("host") and "command" not in event:
        return False
    return True


def _evaluate_rules(rules, event):
    """Run only in an isolated worker; preserve Python's exact regex semantics."""
    for index, (rule, compiled) in enumerate(rules):
        if not _could_apply(rule, event):
            continue
        if compiled.get("command_regex") is not None and not compiled["command_regex"].search(
            event.get("command", {}).get("text", "")
        ):
            continue
        if compiled.get("path_glob") is not None and not compiled["path_glob"].match(
            event.get("file", {}).get("path", "").replace("\\", "/")
        ):
            continue
        if "host_glob" in compiled:
            hosts = (
                [event["network"]["host"]]
                if (event.get("network") or {}).get("host")
                else re.findall(
                    r"https?://(?:[^/\s@'\"]+@)?([a-z0-9.-]+)",
                    event.get("command", {}).get("text", ""),
                    re.I,
                )
                + re.findall(
                    r"(?:^|[\s'\"=])[a-z0-9._-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+):",
                    event.get("command", {}).get("text", ""),
                    re.I,
                )
            )
            if not hosts or (compiled["host_glob"] is not None
                             and not any(compiled["host_glob"].match(h) for h in hosts)):
                continue
        if any(matcher is None for matcher in compiled.values()):
            return index, "an applicable rule has an invalid matcher"
        return index, None
    return None, None
