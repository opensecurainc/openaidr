"""Cost analytics over native per-request logs, scoped to the signed-in tenant.

Metrics and traces can repeat the same usage, so they are never added to logs.
Only metadata leaves this module; prompts and tool arguments are not returned.
"""

from collections import defaultdict
from decimal import Decimal
from pathlib import PurePosixPath, PureWindowsPath
import re

from openaidr.core.agent_usage import (
    PRICE_DATE, UNKNOWN, event_time, text, usage, extract as extract_usage,
)
from .telemetry_events import COMMAND_TOOLS, READ_TOOLS, WRITE_TOOLS, _details


RANGES = {"24h": (1, 3600), "7d": (7, 86400), "30d": (30, 86400), "90d": (90, 86400)}
DIMENSIONS = ("user", "model", "project", "activity", "reasoning_effort")
ACTIVITIES = {
    "coding": "Coding",
    "delegation": "Delegation",
    "feature": "Feature Dev",
    "testing": "Testing",
    "exploration": "Exploration",
    "conversation": "Conversation",
    "debugging": "Debugging",
    "build/deploy": "Build/Deploy",
    "refactoring": "Refactoring",
    "brainstorming": "Brainstorming",
    "git": "Git Ops",
    "planning": "Planning",
    "general": "General",
}


def project(attrs):
    named = text(attrs, "project.name", "project")
    if named:
        return named
    for key in ("cwd", "workdir", "project_path", "process.cwd"):
        raw = attrs.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        raw = raw.strip()
        path_type = PureWindowsPath if "\\" in raw or re.match(r"^[A-Za-z]:", raw) else PurePosixPath
        path = path_type(raw)
        if path.name and path.name != "..":
            return path.name[:1024]
    repo = text(attrs, "vcs.repository.name")
    if repo:
        owner = text(attrs, "vcs.owner.name")
        return f"{owner}/{repo}"[:1024] if owner else repo
    return ""


def activity(attrs):
    explicit = text(attrs, "activity", "task.category").lower()
    if explicit in ACTIVITIES:
        return ACTIVITIES[explicit]
    tool = text(attrs, "tool_name", "tool").lower().removeprefix("functions.")
    if tool in {"agent", "task", "spawn_agent", "dispatch_agent"}:
        return "Delegation"
    if tool in WRITE_TOOLS:
        return "Coding"
    if tool in READ_TOOLS or tool in {"websearch", "webfetch", "web_search"}:
        return "Exploration"
    if tool in {"enterplanmode", "exitplanmode", "update_plan"}:
        return "Planning"
    if tool in COMMAND_TOOLS:
        details = _details(attrs)
        command = text(details, "full_command", "command", "cmd", "bash_command")
        if re.search(
            r"\b(pytest|vitest|jest|playwright|go test|cargo test|npm test|pnpm test)\b",
            command,
        ):
            return "Testing"
        if re.search(r"\b(build|deploy|docker|kubectl|terraform)\b", command):
            return "Build/Deploy"
        if re.search(r"\bgit\s", command):
            return "Git Ops"
    return ""


def extract(export):
    """Add server attribution to the shared usage and correlation metadata."""
    for event in extract_usage(export):
        attrs = event.pop("attributes")
        user = (text(attrs, "cursor.user.email", "cursor.user.account_id")
                if event["name"] == "cursor.api_request"
                else text(attrs, "os.user") or text(export, "username"))
        yield {
            **event,
            "user": user or UNKNOWN,
            "project": project({**_details(attrs), **attrs}),
            "activity": activity(attrs),
        }


def normalize(exports, since, until):
    """Reference accounting for reconciliation against the persisted projection."""
    events, seen = [], set()
    for export in exports:
        for event in extract(export):
            if since <= event["time"] < until and event["key"] not in seen:
                events.append(event)
                seen.add(event["key"])
    events.sort(key=lambda e: (e["time"], not e["name"].endswith("user_prompt")))
    current_turn = {}
    contexts = defaultdict(lambda: {"activities": set(), "projects": set()})
    calls = []
    for event in events:
        scope = event["scope"]
        if event["name"].endswith("user_prompt") and scope[-1]:
            current_turn[scope] = event["turn"] or event["time"].isoformat()
        turn = event["turn"] or current_turn.get(scope)
        key = (*scope, turn) if turn and scope[-1] else None
        if key:
            context = contexts[key]
            if event["activity"]:
                context["activities"].add(event["activity"])
            if event["project"]:
                context["projects"].add(event["project"])
        if event["usage"] is not None:
            calls.append({**event, "context": key})
    priority = (
        "Delegation",
        "Coding",
        "Testing",
        "Build/Deploy",
        "Git Ops",
        "Planning",
        "Exploration",
    )
    for call in calls:
        context = contexts.get(
            call["context"], {"activities": set(), "projects": set()}
        )
        call["activity"] = call["activity"] or next(
            (category for category in priority if category in context["activities"]),
            UNKNOWN,
        )
        call["project"] = call["project"] or (
            next(iter(context["projects"]))
            if len(context["projects"]) == 1
            else UNKNOWN
        )
    return calls


def totals():
    return dict(
        cost=Decimal(0),
        calls=0,
        priced_calls=0,
        unpriced_calls=0,
        reported_calls=0,
        calculated_calls=0,
        demo_calls=0,
        tokens=0,
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=0,
        cache_write_tokens=0,
    )


def add(total, call):
    measured = call["usage"]
    total["calls"] += 1
    total["demo_calls"] += int(call["demo"])
    if measured["cost"] is None:
        total["unpriced_calls"] += 1
    else:
        total["cost"] += measured["cost"]
        total["priced_calls"] += 1
        total[measured["source"] + "_calls"] += 1
    for key in (
        "tokens",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    ):
        total[key] += measured[key]


def finish(total):
    cost = total.pop("cost")
    return {**total, "cost_usd": float(cost) if total["priced_calls"] else None}
