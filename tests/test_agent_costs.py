"""Accounting edge cases that can silently overstate or understate spend."""

from decimal import Decimal
from datetime import datetime, timedelta, timezone

import pytest

from openaidr.server.agent_costs import activity, event_time, normalize, project, usage


@pytest.mark.parametrize(("attrs", "expected"), [
    ({"cwd": "/Users/alice/openaidr/"}, "openaidr"),
    ({"workdir": "/work/openaidr/.worktree/costs/dashboard"}, "dashboard"),
    ({"project_path": r"C:\Users\alice\openaidr"}, "openaidr"),
    ({"process.cwd": "C:/work/openaidr/.worktree/task"}, "task"),
    ({"cwd": r"\\server\share\openaidr"}, "openaidr"),
    ({"cwd": "/"}, ""),
    ({"cwd": "C:/"}, ""),
    ({"cwd": ".."}, ""),
    ({"cwd": "."}, ""),
    ({"cwd": None}, ""),
    ({"cwd": "/work/openaidr", "project.name": "Explicit"}, "Explicit"),
    ({"cwd": "/work/openaidr", "vcs.repository.name": "remote-name"}, "openaidr"),
    ({"vcs.repository.name": "openaidr", "vcs.owner.name": "team"}, "team/openaidr"),
])
def test_project_uses_working_folder_names(attrs, expected):
    assert project(attrs) == expected


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, "0.01485"),
        ({"model": "gpt-6.1-sol"}, "0.00291"),
        ({"model": "gpt-6-sol"}, "0.00297"),
        ({"model": "gpt-6-luna"}, "0.0001485"),
        ({"model": "gpt-5.6-sol"}, "0.00594"),
        ({"model": "gpt-5.6-luna"}, "0.000337"),
        ({"service_tier": "priority"}, "0.02970"),
        ({"service_tier": "fast"}, "0.02970"),
        ({"service_tier": "ultrafast"}, "0.08910"),
        ({"service_tier": "flex"}, "0.007425"),
        ({"service_tier": "batch"}, "0.007425"),
        ({"service_tier": "default"}, "0.01485"),
        ({"service_tier": "standard"}, "0.01485"),
        ({"service_tier": "auto"}, "0.01485"),
        ({"model": "gpt-6.1-sol", "service_tier": "ultrafast"}, "0.01746"),
        ({"model": "gpt-6-sol", "service_tier": "fast"}, "0.00594"),
        ({"model": "gpt-5.6-sol", "service_tier": "priority"}, "0.01188"),
        ({"model": "gpt-5.6-sol", "service_tier": "flex"}, "0.00297"),
        ({"model": "gpt-5.6-sol", "service_tier": "batch"}, "0.00297"),
        ({"model": "gpt-5.6-luna", "service_tier": "priority"}, "0.000674"),
        ({"model": "gpt-5.6-luna", "service_tier": "fast"}, "0.000674"),
        ({"model": "gpt-5.6-luna", "service_tier": "flex"}, "0.0001685"),
        ({"model": "gpt-5.6-luna", "service_tier": "batch"}, "0.0001685"),
        ({"service_tier": "ultrafast", "input_token_count": 272000}, "16.34910"),
        ({"service_tier": "ultrafast", "input_token_count": 272001}, "32.66832"),
        (
            {
                "input_token_count": 300000,
                "cached_token_count": 200000,
                "cache_write_token_count": 0,
                "output_token_count": 1000,
            },
            "2.475",
        ),
        ({"cost_usd": "0", "service_tier": "ultrafast"}, "0"),
        ({"cost_usd": "0.9", "cost_usd_micros": 12000, "service_tier": "ultrafast"}, "0.012"),
    ],
)
def test_price_cache_tiers_long_context_and_reported_precedence(extra, expected):
    attrs = dict(
        model="gpt-6-astra",
        input_token_count="1000",
        output_token_count="200",
        cached_token_count=600,
        cache_write_token_count=100,
        reasoning_token_count=150,
    )
    result = usage({**attrs, **extra}, "codex.sse_event")
    assert result["cost"] == Decimal(expected)
    assert result["source"] == ("reported" if "cost_usd" in extra else "calculated")
    # Reasoning is a subset of output; cache read/write are subsets of input.
    assert result["tokens"] == int(extra.get("input_token_count", 1000)) + int(
        extra.get("output_token_count", 200)
    )
    assert result["tokens"] == sum(
        result[key]
        for key in (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
        )
    )


@pytest.mark.parametrize("model", [
    "gpt-6-sol", "gpt-6-luna", "gpt-5.6-sol", "gpt-5.6-luna", "gpt-6-astra-other",
])
def test_ultrafast_requires_a_published_model_rate(model):
    result = usage(dict(model=model, service_tier="ultrafast",
                        input_token_count=1000, output_token_count=200), "codex.sse_event")
    assert result["cost"] is None and result["source"] == "unpriced"
    assert result["tokens"] == 1200


@pytest.mark.parametrize(
    ("extra", "kind", "when", "expected"),
    [
        ({}, "codex.sse_event", "2026-10-06T07:13:54+00:00", "0"),
        ({"auth_mode": "chatgpt"}, "codex.api_request", "2026-10-08T12:00:00+00:00", "0"),
        ({"service_tier": "priority"}, "codex.sse_event", "2026-10-08T12:00:00+00:00", "0"),
        ({}, "codex.sse_event", "2026-10-06T07:13:53+00:00", None),
        ({}, "codex.sse_event", None, None),
        ({"auth_mode": "ApiKey"}, "codex.sse_event", "2026-10-08T12:00:00+00:00", None),
        ({"auth_mode": ""}, "codex.sse_event", "2026-10-08T12:00:00+00:00", None),
        ({"auth_mode": "unknown"}, "codex.sse_event", "2026-10-08T12:00:00+00:00", None),
        ({"model": "codex-auto-review-other"}, "codex.sse_event", "2026-10-08T12:00:00+00:00", None),
        ({}, "claude_code.api_request", "2026-10-08T12:00:00+00:00", None),
        ({"cost_usd": "0.9"}, "codex.sse_event", "2026-10-08T12:00:00+00:00", "0.9"),
        ({"cost_usd": "0.9", "cost_usd_micros": 12000}, "codex.sse_event", "2026-10-08T12:00:00+00:00", "0.012"),
    ],
)
def test_auto_review_free_quote_requires_chatgpt_and_announced_date(extra, kind, when, expected):
    result = usage(
        dict(model="codex-auto-review", auth_mode="Chatgpt", input_token_count=1000,
             output_token_count=200, cached_token_count=600, cache_write_token_count=100) | extra,
        kind,
        when=datetime.fromisoformat(when) if when else None,
    )
    assert result["cost"] == (Decimal(expected) if expected is not None else None)
    assert result["source"] == (
        "reported" if "cost_usd" in extra else "calculated" if expected is not None else "unpriced"
    )
    assert result["tokens"] == (1900 if kind.startswith("claude_code.") else 1200)


@pytest.mark.parametrize("bad", [-1, True, "NaN", "Infinity", "1.5", {}, 2**54])
@pytest.mark.parametrize("model", ["gpt-6-astra", "codex-auto-review"])
def test_malformed_usage_cannot_be_priced(bad, model):
    assert (
        usage(
            dict(model=model, auth_mode="Chatgpt", input_token_count=bad, output_token_count=200),
            "codex.sse_event",
            when=datetime(2026, 10, 8, tzinfo=timezone.utc),
        )
        is None
    )


def test_unknown_rates_incomplete_usage_and_anthropic_cache_accounting():
    unknown = usage(
        dict(model="unknown", input_token_count=100, output_token_count=20),
        "codex.sse_event",
    )
    assert unknown["cost"] is None and unknown["tokens"] == 120
    unknown_tier = usage(
        dict(
            model="gpt-6-astra",
            input_token_count=100,
            output_token_count=20,
            service_tier="unsupported",
        ),
        "codex.sse_event",
    )
    assert unknown_tier["cost"] is None
    assert (
        usage(
            dict(
                model="gpt-6-astra",
                input_token_count=100,
                output_token_count=20,
                cached_token_count=101,
            ),
            "codex.sse_event",
        )
        is None
    )
    reported = usage(
        dict(
            cost_usd="0.5",
            input_tokens=100,
            output_tokens=20,
            cache_read_tokens=1000,
            cache_creation_tokens=200,
        ),
        "claude_code.api_request",
    )
    assert reported["tokens"] == 1320
    assert reported["cost"] == Decimal("0.5")
    assert reported["source"] == "reported"


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        ({"tool_name": "functions.spawn_agent"}, "Delegation"),
        ({"tool_name": "apply_patch"}, "Coding"),
        (
            {
                "tool_name": "Bash",
                "tool_parameters": '{"full_command":"python -m pytest tests"}',
            },
            "Testing",
        ),
        ({"tool_name": "exec_command", "arguments": '{"cmd":"git status"}'}, "Git Ops"),
        (
            {"tool_name": "exec_command", "arguments": '{"cmd":"npm run build"}'},
            "Build/Deploy",
        ),
        ({"tool_name": "Read"}, "Exploration"),
        ({"activity": "refactoring"}, "Refactoring"),
        ({"prompt": "Please debug and fix this feature"}, ""),
    ],
)
def test_activity_uses_tool_metadata_without_reading_prompts(attrs, expected):
    assert activity(attrs) == expected


@pytest.mark.parametrize(
    "timestamp", ["0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"]
)
@pytest.mark.parametrize("observed", [True, False])
def test_overflowing_event_timestamp_falls_back(timestamp, observed):
    received = datetime(2026, 9, 30, tzinfo=timezone.utc)
    observation = received - timedelta(minutes=1)
    item = (
        {"observedTimeUnixNano": str(int(observation.timestamp() * 1e9))}
        if observed
        else {}
    )
    actual, _ = event_time(item, {"event.timestamp": timestamp}, received)
    assert actual == (observation if observed else received)


def test_event_time_bounds_retries_and_missing_attribution():
    since = datetime(2026, 9, 30, tzinfo=timezone.utc)
    until = since + timedelta(days=1)
    resource = {
        "attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]
    }
    rows = []
    for offset, cost in ((-1, "99"), (0, "0.1"), (86400, "99"), (60, "0.2")):
        when = since + timedelta(seconds=offset)
        rows.append(
            {
                "eventName": "claude_code.api_request",
                "observedTimeUnixNano": str(
                    int((since + timedelta(hours=1)).timestamp() * 1e9)
                ),
                "attributes": [
                    {
                        "key": "event.timestamp",
                        "value": {"stringValue": when.isoformat()},
                    },
                    {"key": "cost_usd", "value": {"stringValue": cost}},
                ],
            }
        )
    # Coarse timestamps can give two legitimate requests identical metadata.
    rows.insert(2, dict(rows[1]))
    # Preserve multiplicity within a batch while deduplicating re-batched
    # deliveries. Observation time is not bill time.
    exports = [
        {
            "id": i,
            "sensor_id": "sensor",
            "received_at": until,
            "payload": {
                "resourceLogs": [
                    {"resource": resource, "scopeLogs": [{"logRecords": rows}]}
                ]
            },
        }
        for i in ("first", "retry")
    ]
    calls = normalize(exports, since, until)
    assert len(calls) == 3
    assert sum(call["usage"]["cost"] for call in calls) == Decimal("0.4")
    assert all(
        call["user"] == call["project"] == call["activity"] == "Unattributed"
        for call in calls
    )
