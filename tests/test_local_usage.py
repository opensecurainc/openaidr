"""Offline desktop accounting through the real local export queue and bridge."""

from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from zoneinfo import ZoneInfo

import httpx
import psutil
import pytest

from openaidr.core.telemetry import encode_export, response_bytes
from openaidr.sensor import bridge, hooks, usage, usage_import
from openaidr.sensor.telemetry import ExportQueue, QueueFull, Telemetry
from test_telemetry_dashboard import cost_payload
from test_telemetry_sensor import config


@pytest.fixture
def local_timezone(monkeypatch):
    @contextmanager
    def change(name):
        with monkeypatch.context() as env:
            env.setenv("TZ", name)
            time.tzset()
            try:
                yield
            finally:
                env.undo()
                time.tzset()
    return change


@pytest.fixture
def clock(monkeypatch, local_timezone):
    class Clock(datetime):
        current = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)

        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz)

    monkeypatch.setattr(usage, "datetime", Clock)
    with local_timezone("UTC"):
        yield Clock


def body(when, *events):
    return encode_export("logs", cost_payload("codex", when, list(events)), "application/json")


def event(ident, **extra):
    return ("codex.sse_event", {
        "event.kind": "response.completed", "response_id": ident,
        "model": "gpt-6.1-sol", "input_token_count": "1000",
        "output_token_count": "200", "effort": "high", **extra,
    })


def read(cfg, days=30):
    return bridge.handle({"action": "usage.summary", "config_path": str(cfg.path), "params": {"days": days}})


@pytest.fixture
def history_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    monkeypatch.setenv("GEMINI_CLI_HOME", str(home))
    monkeypatch.setattr(hooks, "settings_path", lambda agent="claude", config=None:
                        hooks.agent_home(agent, config) / hooks.HOMES[agent][2])
    return home


def write_history(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return path


def codex_history(clock):
    def counts(incoming, cached, outgoing):
        return dict(input_tokens=incoming, cached_input_tokens=cached, output_tokens=outgoing,
                    reasoning_output_tokens=outgoing // 2, total_tokens=incoming + outgoing)

    rows = [
        {"type": "session_meta", "payload": {"id": "session-one"}},
        {"type": "turn_context", "payload": {"turn_id": "turn-one", "model": "gpt-6.1-sol", "effort": "high"}},
    ]
    for days, total, last in (
        (35, counts(1000, 400, 100), counts(1000, 400, 100)),
        (10, counts(3000, 1000, 300), counts(2000, 600, 200)),
        (9, counts(3000, 1000, 300), counts(2000, 600, 200)),  # repeated quota update
        (2, counts(4000, 1500, 400), counts(1000, 500, 100)),
        (-1, counts(5000, 2000, 500), counts(1000, 500, 100)),
    ):
        rows.append({"type": "event_msg", "timestamp": (clock.current - timedelta(days=days)).isoformat(),
                     "payload": {"type": "token_count", "info": {"total_token_usage": total, "last_token_usage": last}}})
    return rows


def claude_history(when, ident="msg-one", output=30, **usage_fields):
    return {"type": "assistant", "timestamp": when.isoformat(), "sessionId": "claude-session", "effort": "high",
            "message": {"id": ident, "model": "claude-sonnet-4-6", "content": "private-history-sentinel",
                        "usage": {"input_tokens": 10, "output_tokens": output, "cache_read_input_tokens": 100,
                                  "cache_creation_input_tokens": 20,
                                  "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 20},
                                  **usage_fields}}}


def test_first_launch_imports_usage_locally_and_restart_keeps_the_same_totals(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    custom = history_home / "codex-account"
    cfg["hooks"] = {"homes": {"codex": str(custom)}}
    cfg.save()
    rows = codex_history(clock)
    path = write_history(custom / "sessions/2026/09/01/rollout-one.jsonl", rows)
    write_history(custom / "archived_sessions/rollout-copy.jsonl", rows)
    when = clock.current - timedelta(days=3)
    write_history(history_home / ".claude/projects/project/session/subagents/agent-one.jsonl",
                  [claude_history(when, output=1), claude_history(when)])
    before = path.read_bytes()
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        result = read(cfg)
        assert result["summary"] == dict(calls=3, priced_calls=3, tokens=3460, cost_usd=pytest.approx(0.00754),
                                        cached_input_tokens=1200, uncached_input_tokens=1930, output_tokens=330,
                                        unclassified_tokens=0)
        assert {row["application"] for row in result["breakdown"]} == {"codex", "claude_code"}
        assert sum(day["calls"] > 0 for day in result["series"]) == 3
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
        assert "private-history-sentinel" not in "\n".join(telemetry.queue.db.iterdump())
        assert path.read_bytes() == before
    finally:
        telemetry.close()
    # A completed import neither adds newly copied old files nor changes totals.
    write_history(history_home / ".claude/projects/project/new.jsonl", [claude_history(when, ident="later-copy")])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg) == result
    finally:
        telemetry.close()


def test_history_import_respects_native_cutoff_including_late_delivery(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    write_history(history_home / ".codex/sessions/rollout.jsonl", codex_history(clock))
    telemetry = Telemetry(cfg)
    try:
        telemetry.accept("logs", body(clock.current - timedelta(days=5), event("native")), "application/json")
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["summary"]["tokens"] == 3400  # history before the first native day only
        telemetry.accept("logs", body(clock.current - timedelta(days=10), event("late-native", input_token_count=2000, cached_token_count=600)), "application/json")
        result = read(cfg)
        assert result["summary"]["calls"] == 2
        assert result["summary"]["tokens"] == 3400
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls WHERE event_key LIKE 'history:%'").fetchone()[0] == 1
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 2
    finally:
        telemetry.close()


@pytest.mark.parametrize("application", ["claude_code", "gemini"])
@pytest.mark.parametrize("batch_size", [1, 1000])
def test_interrupted_history_import_resumes_without_duplicating_streamed_messages(tmp_path, clock, history_home, monkeypatch, application, batch_size):
    cfg = config(tmp_path)
    when = clock.current - timedelta(days=2)
    if application == "gemini":
        first = gemini_history(when)
        first["tokens"]["output"] = 1
        path = write_history(history_home / ".gemini/tmp/project/chats/session.jsonl",
                             [first, gemini_history(when), gemini_history(when, ident="second")])
        partial, complete, cost = 4351, 5600, 0.007828
    else:
        path = write_history(history_home / ".claude/projects/project/session.jsonl",
                             [claude_history(when, output=1), claude_history(when), claude_history(when, ident="second")])
        partial, complete, cost = 3431, 3620, 0.00817
    write_history(history_home / ".codex/sessions/rollout.jsonl", codex_history(clock))
    monkeypatch.setattr(usage_import, "BATCH_SIZE", batch_size)
    telemetry = Telemetry(cfg)
    original = Path.open

    class InterruptedFile:
        def __init__(self):
            self.source = original(path, "rb")
            self.lines = 0

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.source.close()

        def readline(self, size):
            self.lines += 1
            if self.lines == 2:
                raise OSError("disk temporarily unavailable")
            return self.source.readline(size)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", lambda self, *args, **kwargs: InterruptedFile() if self == path else original(self, *args, **kwargs))
            assert not usage_import.run_once(cfg, telemetry.queue, threading.Event())
        assert read(cfg)["summary"]["tokens"] == partial  # Other readable logs still import.
        # Reproduce the old sensor's pending-import query: it must not select
        # Gemini and feed Claude logs into its later import boundary on rollback.
        legacy_pending = telemetry.queue.db.execute("SELECT application FROM usage_imports WHERE scope=? AND completed=0",
                                                    (telemetry.queue.usage_scope,)).fetchall()
        assert "gemini" not in {row[0] for row in legacy_pending}
        telemetry.close()
        telemetry = Telemetry(cfg)
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["tokens"] == complete
        assert read(cfg)["summary"]["calls"] == 4
        assert read(cfg)["summary"]["cost_usd"] == pytest.approx(cost)
    finally:
        telemetry.close()


@pytest.mark.parametrize("application", ["codex", "claude_code", "gemini"])
@pytest.mark.parametrize("escaped", [False, True])
def test_history_parser_preserves_accounting_without_decoding_content(tmp_path, clock, application, escaped):
    when = clock.current - timedelta(hours=2)
    if application == "codex":
        rows = codex_history(clock)
        rows[0]["payload"]["base_instructions"] = {"text": "private-history-sentinel" * 1000}
        rows[1]["payload"]["developer_instructions"] = "private-history-sentinel" * 1000
        rows[1]["payload"]["reasoning.effort"] = {"level": "ultra"}
        rows.insert(2, {"type": "response_item", "payload": {
            "content": "private-history-sentinel" * 1000, "model": "wrong-model"}})
    elif application == "claude_code":
        rows = [claude_history(when), {"type": "user", "message": {"content": "private-history-sentinel" * 1000}}]
        rows[0]["message"]["content"] = [{"type": "text", "text": "private-history-sentinel" * 1000}]
    else:
        rows = [gemini_history(when), {"type": "user", "content": "private-history-sentinel" * 1000}]
        rows[0]["content"] = "private-history-sentinel" * 1000
    source = "".join(json.dumps(row) + "\n" for row in rows)
    if escaped:
        source = source.replace('"type"', '"t\\u0079pe"').replace("token_count", "token\\u005fcount")
        source = source.replace('"usage"', '"us\\u0061ge"').replace('"tokens"', '"t\\u006fkens"')
    path = tmp_path / "session.jsonl"
    path.write_text(source)
    selected = list(usage_import.records(path, threading.Event(), lambda: False, application))
    assert "private-history-sentinel" not in json.dumps(selected)

    def accounting(records):
        state = {}
        result = []
        for record in records:
            item = (usage_import.codex(record, state) if application == "codex" else
                    usage_import.claude(record) if application == "claude_code" else usage_import.gemini(record))
            if item:
                result.append(item)
        return result

    assert accounting(selected) == accounting(map(json.loads, source.splitlines()))
    if application == "gemini":
        path = tmp_path / "session.json"
        path.write_text(json.dumps({"messages": [False, *rows], "content": "private-history-sentinel" * 1000}))
        selected = list(usage_import.records(path, threading.Event(), lambda: False, application))
        assert "private-history-sentinel" not in json.dumps(selected)
        assert accounting(selected) == accounting(rows)


@pytest.mark.parametrize("batch_size", [2, 1000])
def test_history_prioritizes_recent_usage_and_compacts_only_after_import(tmp_path, clock, history_home, monkeypatch, batch_size):
    cfg = config(tmp_path)
    rows = codex_history(clock)[:-1]
    rows.append({"type": "event_msg", "timestamp": (clock.current - timedelta(hours=6)).isoformat(),
                 "payload": {"type": "token_count", "info": {"total_token_usage": {
                     "input_tokens": 5000, "cached_input_tokens": 2000, "output_tokens": 500}}}})
    write_history(history_home / ".codex/sessions/long-running.jsonl", rows)
    write_history(history_home / ".claude/projects/project/session.jsonl", [
        claude_history(clock.current - timedelta(days=20), ident="oldest"),
        claude_history(clock.current - timedelta(days=3), ident="older"),
        claude_history(clock.current - timedelta(hours=1), ident="recent"),
    ])
    write_history(history_home / ".gemini/tmp/project/chats/session.jsonl", [
        gemini_history(clock.current - timedelta(days=5), ident="old-gemini"),
        gemini_history(clock.current - timedelta(hours=2), ident="recent-gemini"),
    ])
    monkeypatch.setattr(usage_import, "BATCH_SIZE", batch_size)
    monkeypatch.setattr(usage, "MAX_RECORDS", 2)
    telemetry = Telemetry(cfg)
    written, seen, compactions = [], set(), []
    store, compact = usage_import.store, usage._compact

    def capture(queue, application, events):
        store(queue, application, events)
        for key, when in queue.db.execute("SELECT event_key,happened_at FROM usage_calls ORDER BY rowid"):
            if key not in seen:
                written.append(when)
                seen.add(key)

    def compact_after_import(db, before, limit):
        assert not db.execute("SELECT 1 FROM usage_imports WHERE completed IN (0,2)").fetchone()
        compactions.append(limit)
        compact(db, before, limit)

    monkeypatch.setattr(usage_import, "store", capture)
    monkeypatch.setattr(usage, "_compact", compact_after_import)
    try:
        assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
        recent = clock.current.timestamp() - 86400
        assert len(written) == 8
        assert all(when >= recent for when in written[:3])
        assert written[3:] == sorted(written[3:], reverse=True)
        assert compactions
        result = read(cfg)
        assert result["summary"]["calls"] == 8
        assert result["summary"]["tokens"] == 7180
        assert result["periods"]["1"]["summary"]["calls"] == 3
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 3
        assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
        assert read(cfg) == result
    finally:
        telemetry.close()


def test_priority_import_keeps_canonical_duplicates_and_recovers_prices(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    when = clock.current - timedelta(days=4)
    first = claude_history(when, ident="same-count", speed="unknown")
    conflicting = claude_history(when + timedelta(days=1), ident="same-count")
    recovered = claude_history(when, ident="same-count")
    write_history(history_home / ".claude/projects/project/session.jsonl", [
        first, conflicting, recovered,
        claude_history(when, ident="streamed", output=1),
        claude_history(when + timedelta(days=2), ident="streamed", output=50),
    ])
    monkeypatch.setattr(usage_import, "BATCH_SIZE", 2)
    telemetry = Telemetry(cfg)
    try:
        assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
        calls = telemetry.queue.db.execute("SELECT happened_at,tokens,cost_usd FROM usage_calls ORDER BY happened_at").fetchall()
        assert [tuple(row) for row in calls] == [
            (when.timestamp(), 160, pytest.approx(float(usage_import.claude(recovered)["usage"]["cost"]))),
            ((when + timedelta(days=2)).timestamp(), 180, pytest.approx(float(usage_import.claude(
                claude_history(when, output=50))["usage"]["cost"]))),
        ]
    finally:
        telemetry.close()


def test_large_history_batch_reuses_original_enrollment_with_legacy_sqlite_limit(tmp_path, clock):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="current")
    events = [usage_import.claude(claude_history(clock.current - timedelta(days=2), ident=str(index)))
              for index in range(1001)]
    try:
        queue.db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        with queue.db:
            queue.db.execute("INSERT INTO usage_imports VALUES ('current','claude_code',?,0)",
                             (clock.current.timestamp(),))
            usage.record_calls(queue.db, "previous", events[:600])
        usage_import.store(queue, "claude_code", events)
        assert dict(queue.db.execute("SELECT scope,count(*) FROM usage_calls GROUP BY scope")) == {
            "previous": 600, "current": 401,
        }
        result = read(cfg)
        assert result["summary"]["calls"] == 1001
        assert result["summary"]["tokens"] == 160160
    finally:
        queue.close()


@pytest.mark.parametrize("interrupt_after", [1, 2])
def test_priority_import_resumes_after_cancellation_without_losing_days(tmp_path, clock, history_home, monkeypatch, interrupt_after):
    cfg = config(tmp_path)
    write_history(history_home / ".claude/projects/project/session.jsonl", [
        claude_history(clock.current - timedelta(days=10), ident="oldest"),
        claude_history(clock.current - timedelta(days=2), ident="older"),
        claude_history(clock.current - timedelta(hours=1), ident="recent"),
    ])
    monkeypatch.setattr(usage_import, "BATCH_SIZE", 1)
    stop = threading.Event()
    telemetry = Telemetry(cfg)
    original = usage_import.store
    written = set()

    def interrupt(queue, application, events):
        original(queue, application, events)
        written.update(item["key"] for item in events)
        if len(written) >= interrupt_after:
            stop.set()

    try:
        with monkeypatch.context() as patch:
            patch.setattr(usage_import, "store", interrupt)
            assert not usage_import.run_once(cfg, telemetry.queue, stop)
        assert read(cfg)["summary"]["calls"] == interrupt_after
        assert telemetry.queue.db.execute("SELECT completed FROM usage_imports WHERE application='claude_code'").fetchone()[0] == 0
        assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
        report = read(cfg)
        assert report["summary"]["calls"] == 3
        assert report["summary"]["tokens"] == 480
        assert report["periods"]["1"]["summary"]["calls"] == 1
        assert sum(day["calls"] > 0 for day in report["series"]) == 3
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
    finally:
        telemetry.close()


@pytest.mark.parametrize("mode", ["missing", "malformed", "disabled", "paused", "stopped"])
def test_unavailable_or_disabled_history_keeps_zero_usage(tmp_path, clock, history_home, monkeypatch, mode):
    cfg = config(tmp_path, enabled=mode != "disabled")
    stop = threading.Event()
    if mode == "stopped":
        stop.set()
    if mode != "missing":
        path = write_history(history_home / ".claude/projects/project/session.jsonl",
                             [claude_history(clock.current - timedelta(days=2))])
        if mode == "malformed":
            monkeypatch.setattr(usage_import, "LINE_LIMIT", 1024)
            path.write_bytes(b'invalid\n' + b'x' * 2048 + b'\n\xff\n[]\n' +
                             json.dumps(claude_history(clock.current - timedelta(days=2), input_tokens=-1)).encode() + b'\n' +
                             b'{"type":"assistant","message":{"usage":true}}\n')
    telemetry = Telemetry(cfg)
    try:
        usage_import.run_once(cfg, telemetry.queue, stop, paused=lambda: mode == "paused")
        result = read(cfg)
        assert result["summary"]["tokens"] == result["summary"]["calls"] == 0
        assert all(day["calls"] == 0 for day in result["series"])
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
    finally:
        telemetry.close()


def test_import_survives_new_enrollment_without_copying_or_uploading_history(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    write_history(history_home / ".codex/sessions/rollout.jsonl", codex_history(clock))
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
    finally:
        telemetry.close()
    clock.current -= timedelta(seconds=1)
    cfg["tenant_id"] = "another-tenant"
    cfg.save()
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 2
        assert telemetry.queue.status()["queue_depth"] == 0
    finally:
        telemetry.close()


def test_upgrade_recovers_local_usage_from_previous_enrollments(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    started = (clock.current - timedelta(days=5)).timestamp()
    write_history(history_home / ".codex/sessions/rollout.jsonl", codex_history(clock))
    packets = [body(clock.current - timedelta(days=days), event(ident))
               for days, ident in ((4, "first"), (1, "latest"))]
    for scope, packet in zip(("original-enrollment", "later-enrollment"), packets):
        queue = ExportQueue(path, usage_scope=scope)
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        queue.close()
    with sqlite3.connect(path) as db:
        db.execute("UPDATE usage_history SET started_at=? WHERE scope='original-enrollment'", (started,))
        # Older sensors could retain the same response under two enrollments.
        db.execute("INSERT INTO usage_calls SELECT 'copied-enrollment',event_key,happened_at-3600,model,effort,tokens,cost_usd "
                   "FROM usage_calls WHERE scope='later-enrollment'")
    cfg.update(server_url="https://another.example", tenant_id="another-tenant", sensor_id="another-sensor")
    cfg.save()
    reader = usage.UsageReader()
    before = usage.overview(cfg, 30, reader)
    assert before["summary"]["calls"] == 2
    assert before["summary"]["tokens"] == 2400
    assert before["tracking_started_at"] == datetime.fromtimestamp(started, timezone.utc).isoformat()
    telemetry = Telemetry(cfg)
    try:
        assert telemetry.queue.usage_scope == "original-enrollment"
        telemetry.import_usage(threading.Event())
        imported = usage.overview(cfg, 30, reader)
        assert imported["summary"]["calls"] == 3
        assert imported["summary"]["tokens"] == 4600
        assert imported["tracking_started_at"] == before["tracking_started_at"]
        assert telemetry.queue.status()["queue_depth"] == 0
        # A replay preserves the previous enrollment's row and token details.
        telemetry.accept("logs", packets[1], "application/json")
        assert usage.overview(cfg, 30, reader)["summary"] == imported["summary"]
        with telemetry.queue.db:
            telemetry.queue.db.execute("UPDATE usage_calls SET cost_usd=1 WHERE scope='later-enrollment'")
        assert usage.overview(cfg, 30, reader) == usage.overview(cfg, 30)
        after = usage.overview(cfg, 30, reader)
        assert after["summary"]["cost_usd"] > imported["summary"]["cost_usd"]
    finally:
        reader.close()
        telemetry.close()
    cfg.update(tenant_id="third-tenant", sensor_id="third-sensor")
    cfg.save()
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"] == after["summary"]
    finally:
        telemetry.close()
    cfg["data_dir"] = str(tmp_path / "separate-profile")
    cfg.save()
    assert read(cfg)["summary"]["calls"] == 0


def test_codex_fork_replay_and_counter_resets_do_not_add_inherited_usage(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    rows = codex_history(clock)[:-1]
    write_history(history_home / ".codex/sessions/parent.jsonl", rows)
    fork = json.loads(json.dumps(rows))
    fork[0]["payload"] = {"id": "fork", "forked_from_id": "session-one",
                          "timestamp": (clock.current - timedelta(days=1)).isoformat()}
    fork.extend([
        {"type": "turn_context", "payload": {"model": "gpt-6.1-sol", "turn_id": "new-turn"}},
        {"type": "event_msg", "timestamp": (clock.current - timedelta(hours=2)).isoformat(),
         "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 5000, "output_tokens": 500, "cached_input_tokens": 2000}}}},
        {"type": "event_msg", "timestamp": (clock.current - timedelta(hours=1)).isoformat(),
         "payload": {"type": "token_count", "info": {"total_token_usage": {"input_tokens": 100, "output_tokens": 10}}}},
    ])
    write_history(history_home / ".codex/sessions/fork.jsonl", fork)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        result = read(cfg)
        assert result["summary"]["calls"] == 3
        assert result["summary"]["tokens"] == 4400
    finally:
        telemetry.close()


@pytest.mark.parametrize("fields,expected", [
    ({}, 0.00063),
    ({"cache_creation": {"ephemeral_5m_input_tokens": 20}}, 0.000585),
    ({"inference_geo": "us"}, 0.000693),
    ({"speed": "unknown"}, None),
    ({"cache_creation": {"ephemeral_1h_input_tokens": 21}}, None),
])
def test_imported_claude_cost_uses_recorded_cache_duration_and_known_modifiers(clock, fields, expected):
    result = usage_import.claude(claude_history(clock.current, **fields))
    cost = result["usage"]["cost"]
    assert result["usage"]["tokens"] == 160
    assert (float(cost) if cost is not None else None) == (pytest.approx(expected) if expected is not None else None)


@pytest.mark.parametrize("fields,expected", [
    ({}, 0.002025),
    ({"cache_creation": {"ephemeral_5m_input_tokens": 20}}, 0.001875),
    ({"inference_geo": "us"}, 0.0022275),
    ({"service_tier": "batch"}, None),
    ({"speed": "fast"}, None),
])
def test_fable_history_uses_published_cache_prices(clock, fields, expected):
    record = claude_history(clock.current, **fields)
    record["message"]["model"] = "claude-fable-5-1"
    cost = usage_import.claude(record)["usage"]["cost"]
    assert (float(cost) if cost is not None else None) == (pytest.approx(expected) if expected is not None else None)


def test_upgraded_import_recovers_missing_prices_without_replacing_known_costs(tmp_path, clock, history_home, monkeypatch):
    from openaidr.core import hook_estimates

    cfg = config(tmp_path)
    rows = [claude_history(clock.current - timedelta(days=2), ident=ident) for ident in ("missing", "quoted")]
    for row in rows:
        row["message"]["model"] = "claude-fable-5-1"
    write_history(history_home / ".claude/projects/one/log.jsonl", rows)
    telemetry = Telemetry(cfg)
    try:
        with monkeypatch.context() as old:
            old.delitem(hook_estimates.RATES, "claude-fable-5-1")
            telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["priced_calls"] == 0
        quoted = usage_import.claude(rows[1])["key"]
        with telemetry.queue.db:
            telemetry.queue.db.execute("UPDATE usage_calls SET cost_usd=0.5 WHERE event_key=?", (quoted,))
            # An older sensor has no completed source/pricing revision.
            telemetry.queue.db.execute("DELETE FROM usage_import_sources")
        telemetry.import_usage(threading.Event())
        result = read(cfg)["summary"]
        assert result["calls"] == 2 and result["tokens"] == 320
        assert result["priced_calls"] == 2 and result["cost_usd"] == pytest.approx(0.502025)
        monkeypatch.setattr(usage_import, "files", lambda *_: pytest.fail("unchanged history must not be rescanned"))
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"] == result
        assert telemetry.queue.status()["queue_depth"] == 0
    finally:
        telemetry.close()


def test_import_watches_recorded_profiles_and_preserves_cutoff_and_deduplication(tmp_path, clock, history_home, monkeypatch):
    from openaidr.sensor import integrations

    cfg = config(tmp_path)
    original = codex_history(clock)
    write_history(history_home / ".codex/sessions/one.jsonl", original)
    profile = history_home / "custom-profile"
    copied = json.loads(json.dumps(original))
    copied[0]["payload"]["id"] = "session-two"
    copied[1]["payload"]["turn_id"] = "turn-two"
    write_history(profile / "sessions/two.jsonl", copied)
    write_history(profile / "archived_sessions/duplicate.jsonl", original)
    integrations.manifest_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    integrations.manifest_path(cfg).write_text(json.dumps({str(history_home / ".codex/config.toml"): {"agent": "codex"}}))
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        before = read(cfg)["summary"]
        cutoff = telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='codex'").fetchone()[0]
        scans = []
        files = usage_import.files
        monkeypatch.setattr(usage_import, "files", lambda *args: (scans.append(args[1]), files(*args))[1])

        class Stop:
            polls = 0

            def is_set(self):
                return self.polls == 2

            def wait(self, _):
                self.polls += 1
                cfg["hooks"] = {"homes": {"codex": str(profile)}}
                cfg.save()

        telemetry.import_usage(Stop(), watch=True)
        after = read(cfg)["summary"]
        assert scans == ["codex"]
        assert after["calls"] == before["calls"] * 2
        assert after["tokens"] == before["tokens"] * 2
        assert after["cost_usd"] == pytest.approx(before["cost_usd"] * 2)
        assert telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='codex'").fetchone()[0] == cutoff
        telemetry.import_usage(threading.Event())
        assert scans == ["codex"] and read(cfg)["summary"] == after
        assert "private-history-sentinel" not in "\n".join(telemetry.queue.db.iterdump())
    finally:
        telemetry.close()


def gemini_history(when, ident="gemini-one", model="gemini-2.5-flash"):
    return dict(id=ident, timestamp=when.isoformat(), type="gemini", model=model,
                content="private transcript content", tokens=dict(input=1000, output=100, cached=800, thoughts=50))


def test_gemini_json_and_jsonl_history_import_on_upgrade_is_local_and_idempotent(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    now = clock.current
    clock.current -= timedelta(days=40)
    telemetry = Telemetry(cfg)
    started = clock.current.isoformat()
    clock.current = now
    message = gemini_history(now - timedelta(days=2))
    home = history_home / "custom-gemini-home"
    monkeypatch.setenv("GEMINI_CLI_HOME", str(home))
    path = write_history(home / ".gemini/tmp/project/chats/session-old.json", [])
    path.write_text(json.dumps({"sessionId": "one", "messages": [message, None, {"type": "user"}]}))
    write_history(path.with_suffix(".jsonl"), [
        {"sessionId": "one"}, {**message, "tokens": None}, message, message,
        gemini_history(now - timedelta(days=1), ident="gemini-two", model="unknown-model"),
        gemini_history(now - timedelta(days=35), ident="expired"),
        gemini_history(now + timedelta(days=1), ident="future"),
        {**message, "id": "invalid", "tokens": {"input": -1, "output": 100}},
    ])
    # The JSON parser must not inspect agent databases or files outside chats.
    write_history(path.with_suffix(".sqlite"), [gemini_history(now - timedelta(days=1), ident="database")])
    write_history(path.parent.parent / "settings.jsonl", [gemini_history(now - timedelta(days=1), ident="settings")])
    try:
        telemetry.import_usage(threading.Event())
        result = read(cfg)
        assert result["tracking_started_at"] == started
        assert all(period["tracking_started_at"] == started for period in result["periods"].values())
        assert result["summary"] == dict(calls=2, priced_calls=1, tokens=2300, cost_usd=pytest.approx(0.000459),
            cached_input_tokens=1600, uncached_input_tokens=400, output_tokens=300, unclassified_tokens=0)
        assert {row["application"] for row in result["breakdown"]} == {"gemini"}
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
        assert "private transcript content" not in "".join(telemetry.queue.db.iterdump())
        cutoff = telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='gemini'").fetchone()[0]
        telemetry.close()
        clock.current += timedelta(minutes=1)
        telemetry = Telemetry(cfg)
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"] == result["summary"]
        assert read(cfg)["tracking_started_at"] == started
        assert telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='gemini'").fetchone()[0] == cutoff
    finally:
        telemetry.close()


def test_malformed_and_oversized_gemini_json_does_not_stop_other_history(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    monkeypatch.setattr(usage_import, "DOCUMENT_LIMIT", 1024)
    root = history_home / ".gemini/tmp/project/chats"
    for name, content in {"large": b'x' * 2048, "broken": b'{', "list": b'[]', "invalid": b'\xff',
                          "messages": b'{"messages":false}'}.items():
        path = write_history(root / f"session-{name}.json", [])
        path.write_bytes(content)
    write_history(history_home / ".claude/projects/project/session.jsonl", [claude_history(clock.current - timedelta(days=1))])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert {row["application"] for row in read(cfg)["breakdown"]} == {"claude_code"}
    finally:
        telemetry.close()


@pytest.mark.parametrize("model,incoming,cached,outgoing,thoughts,expected", [
    ("gemini-2.5-pro", 200_000, 100_000, 100, 50, 0.139),
    ("gemini-2.5-pro", 200_001, 100_000, 100, 50, 0.2772525),
    ("gemini-3.1-pro-preview", 200_001, 100_000, 100, 50, 0.442704),
    ("gemini-3-flash-preview", 1000, 800, 100, 50, 0.00059),
    ("gemini-4-argon", 1000, 800, 100, 50, 0.00198),
    ("unknown-model", 1000, 800, 100, 50, None),
])
def test_gemini_cache_and_thinking_tokens_use_standard_rates(clock, model, incoming, cached, outgoing, thoughts, expected):
    record = gemini_history(clock.current, model=model)
    record["tokens"] = dict(input=incoming, cached=cached, output=outgoing, thoughts=thoughts)
    result = usage_import.gemini(record)["usage"]
    assert result["tokens"] == incoming + outgoing + thoughts
    assert result["input_tokens"] == incoming - cached
    assert result["output_tokens"] == outgoing + thoughts
    assert (float(result["cost"]) if result["cost"] is not None else None) == (pytest.approx(expected) if expected is not None else None)
    if model == "gemini-4-argon":
        record["timestamp"] = "2026-12-01T00:00:00Z"
        assert float(usage_import.gemini(record)["usage"]["cost"]) == pytest.approx(expected * 2)


@pytest.mark.parametrize("zone", ["UTC", "America/Los_Angeles", "Asia/Kathmandu"])
def test_persistent_usage_matches_snapshot_after_updates_expiry_and_identity_changes(tmp_path, clock, local_timezone, zone):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    reader = usage.UsageReader()
    clock.current = datetime(2026, 11, 1, 9, 30, tzinfo=timezone.utc)
    with local_timezone(zone):
        def compare():
            cached = usage.overview(cfg, 30, reader)
            fresh = usage.overview(cfg, 30)
            assert cached == fresh
            return cached

        try:
            old = clock.current - timedelta(days=3)
            boundary = clock.current - timedelta(hours=24) + timedelta(seconds=5)
            for when, ident in ((old, "old"), (boundary, "boundary"),
                                (clock.current - timedelta(seconds=1), "current"),
                                (clock.current + timedelta(seconds=5), "future")):
                telemetry.accept("logs", body(when, event(ident)), "application/json")
            assert compare()["summary"]["calls"] == 3
            clock.current += timedelta(seconds=10)
            assert compare()["periods"]["1"]["summary"]["calls"] == 2
            telemetry.accept("logs", body(old, event("late-old")), "application/json")
            assert compare()["summary"]["calls"] == 5
            db = telemetry.queue.db
            scope = usage.identity(cfg)
            with db:
                key = db.execute("SELECT event_key FROM usage_calls WHERE happened_at=? LIMIT 1", (old.timestamp(),)).fetchone()[0]
                db.execute("UPDATE usage_calls SET cost_usd=2 WHERE scope=? AND event_key=?", (scope, key))
                db.execute("UPDATE usage_tokens SET cached_input_tokens=10 WHERE scope=? AND event_key=?", (scope, key))
                db.execute("UPDATE usage_apps SET application='claude_code' WHERE scope=? AND event_key=?", (scope, key))
            assert compare()["summary"]["cost_usd"] > 2
            with db:
                db.execute("UPDATE usage_calls SET happened_at=? WHERE scope=? AND event_key=?",
                           ((clock.current - timedelta(hours=1)).timestamp(), scope, key))
            compare()
            with db:
                db.execute("DELETE FROM usage_calls WHERE scope=? AND event_key=?", (scope, key))
            assert compare()["summary"]["calls"] == 4
            previous = cfg["sensor_id"]
            cfg["sensor_id"] = "different-device"
            assert compare()["summary"]["calls"] == 4
            cfg["sensor_id"] = previous
            compare()
            clock.current += timedelta(days=30)
            assert compare()["summary"]["calls"] == 0
            assert len(reader.hours) <= 722
        finally:
            reader.close()
            telemetry.close()


def test_persistent_usage_reopens_replaced_database_and_supports_older_ledgers(tmp_path, clock):
    cfg = config(tmp_path)
    reader = usage.UsageReader()
    try:
        assert usage.overview(cfg, 30, reader)["summary"]["calls"] == 0
        telemetry = Telemetry(cfg)
        telemetry.accept("logs", body(clock.current - timedelta(seconds=1), event("first")), "application/json")
        assert usage.overview(cfg, 30, reader)["summary"]["calls"] == 1
        telemetry.close()
        path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
        replacement = tmp_path / "replacement.sqlite3"
        with sqlite3.connect(path) as source, sqlite3.connect(replacement) as target:
            source.backup(target)
            target.execute("DELETE FROM usage_calls")
            target.execute("DELETE FROM usage_history")
            triggers = [row[0] for row in target.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '%_revision_%'")]
            for trigger in triggers:
                target.execute(f'DROP TRIGGER "{trigger}"')
            target.execute("DROP TABLE usage_revisions")
        reader.close()  # Windows does not allow replacing an open SQLite file.
        replacement.replace(path)
        empty = usage.overview(cfg, 30, reader)
        assert empty["summary"]["calls"] == 0
        assert empty["tracking_started_at"] is None
        assert empty["history_incomplete"] is True
        with sqlite3.connect(path) as db:
            db.execute("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)",
                       (usage.identity(cfg), "legacy", clock.current.timestamp() - 1, "model", "low", 10, .1))
        assert usage.overview(cfg, 30, reader)["summary"]["calls"] == 1
    finally:
        reader.close()


def test_usage_helper_serves_multiple_reads_rejects_mutations_and_exits_on_eof(tmp_path, clock):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    telemetry.accept("logs", body(datetime.now(timezone.utc) - timedelta(seconds=1), event("one")), "application/json")
    telemetry.close()
    request = {"action": "usage.summary", "config_path": str(cfg.path), "params": {"days": 30}}
    requests = [request, {**request, "action": "setup"}, {**request, "params": {"days": True}}, request]
    command = [sys.executable, "-c", "import psutil, sys; from openaidr.sensor.cli import main; "
               "main(); print(psutil.Process().nice(), file=sys.stderr)", "desktop-usage"]
    parent_priority = psutil.Process().nice()
    result = subprocess.run(command, input="\n".join(json.dumps(item) for item in requests) + "\n",
                            capture_output=True, text=True, timeout=10, check=True)
    priority = int(result.stderr.strip())
    assert priority == (psutil.IDLE_PRIORITY_CLASS if psutil.WINDOWS else max(10, parent_priority))
    assert psutil.Process().nice() == parent_priority
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [item["ok"] for item in responses] == [True, False, False, True]
    assert responses[0]["data"]["summary"]["calls"] == responses[-1]["data"]["summary"]["calls"] == 1
    assert "Only usage.summary" in responses[1]["error"]
    oversized = subprocess.run(command, input="x" * 65537, capture_output=True, text=True, timeout=10, check=True)
    assert json.loads(oversized.stdout)["error"] == "Usage request exceeded the size limit."


def test_usage_helper_still_reads_when_priority_change_is_denied(tmp_path):
    cfg = config(tmp_path)
    command = [sys.executable, "-c", """
import psutil
from unittest.mock import patch
from openaidr.sensor.cli import main
with patch.object(psutil.Process, 'nice', side_effect=psutil.AccessDenied()):
    main()
""", "desktop-usage"]
    request = {"action": "usage.summary", "config_path": str(cfg.path), "params": {"days": 30}}
    result = subprocess.run(command, input=json.dumps(request) + "\n", capture_output=True,
                            text=True, timeout=10, check=True)
    response = json.loads(result.stdout)
    assert response["ok"] is True
    assert response["data"]["summary"]["calls"] == 0


def test_local_usage_survives_upload_restart_and_server_loss(tmp_path, monkeypatch, clock):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    when = clock.current.replace(hour=0) - timedelta(microseconds=1)
    packet = body(when, event("priced"), event("unpriced", model="unknown-model", effort=""),
                  event("demo", **{"openaidr.demo": "true"}))
    telemetry.accept("logs", packet, "application/json")
    telemetry.accept("logs", packet, "application/json")
    telemetry.http.close()
    telemetry.http = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(
        200, content=response_bytes("logs", "application/json"),
        headers={"Content-Type": "application/json"},
    )))
    try:
        before = read(cfg)
        assert before["summary"] == dict(calls=2, priced_calls=1, tokens=2400, cost_usd=.004,
                                        cached_input_tokens=0, uncached_input_tokens=2000,
                                        output_tokens=400, unclassified_tokens=0)
        assert {row["name"]: row["calls"] for row in before["by_reasoning_effort"]} == {"high": 1, "unknown": 1}
        assert sum(row["tokens"] for row in before["series"]) == 2400
        assert before["series"][-2]["tokens"] == before["series"][-1]["tokens"] == 1200
        assert before["source"] == "local" and before["history_incomplete"]
        assert telemetry.forward_once() and telemetry.forward_once()
        assert telemetry.queue.status()["queue_depth"] == 0
    finally:
        telemetry.close()

    def offline(_config):
        raise httpx.ConnectError("network disconnected")

    monkeypatch.setattr(bridge, "Client", type("ClientFactory", (), {"from_config": staticmethod(offline)}))
    # No service or network is needed. A credential rotation keeps the history.
    cfg["sensor_token"] = "replacement-token"
    cfg.save()
    assert read(cfg)["summary"] == before["summary"]
    telemetry = Telemetry(cfg)
    try:
        telemetry.accept("logs", packet, "application/json")
        assert read(cfg, 7)["summary"] == before["summary"]
    finally:
        telemetry.close()
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    with sqlite3.connect(path) as db:
        metadata = json.dumps(db.execute("SELECT * FROM usage_calls").fetchall())
        assert "PRIVATE-PROMPT" not in metadata and "response.completed" not in metadata
        assert "replacement-token" not in metadata and "priced" not in metadata
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    for key in ("server_url", "sensor_id", "tenant_id"):
        previous = cfg.get(key)
        cfg[key] = "different-identity"
        cfg.save()
        assert read(cfg)["summary"] == before["summary"]
        if previous is None:
            cfg.pop(key)
        else:
            cfg[key] = previous
    cfg.save()
    assert read(cfg)["summary"] == before["summary"]


@pytest.mark.parametrize("days", [7, 14])
def test_queued_upgrade_rejection_retention_and_utc_windows(tmp_path, monkeypatch, clock, days):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    # Simulate an old sensor with only raw queued exports.
    queue = ExportQueue(path, max_bytes=4096)
    midnight = clock.current.replace(hour=0)
    packet = body(midnight - timedelta(days=days - 1), event("legacy"))
    ident = queue.append("logs", packet, "application/json", 1)
    queue.close()
    assert read(cfg)["summary"]["calls"] == 0
    queue = ExportQueue(path, max_bytes=4096, usage_scope=usage.identity(cfg))
    try:
        assert queue.next()["batch_id"] == ident
        queue.confirm(ident)
        # The old retained record was projected before the upload deleted it.
        result = read(cfg, days)
        assert len(result["series"]) == days
        assert result["series"][0]["date"] == (midnight - timedelta(days=days - 1)).date().isoformat()
        assert result["series"][0]["tokens"] == 1200
        older = body(midnight - timedelta(days=29), event("oldest"))
        expired = body(midnight - timedelta(days=30), event("expired"))
        future = body(clock.current + timedelta(days=1), event("future"))
        for item in (older, expired, future):
            queue.append("logs", item, "application/json", 1)
        assert read(cfg, days)["summary"]["calls"] == 1
        assert read(cfg, 30)["summary"]["calls"] == 2
        assert read(cfg, 30)["series"][0]["tokens"] == 1200
        # Rejected exports must not contribute to the ledger.
        extra = body(midnight, event("rejected"))
        with pytest.raises(QueueFull):
            queue.append_many([dict(signal="logs", body=extra, content_type="application/json", records=1)] * 10)
        assert read(cfg)["summary"]["calls"] == 2
        monkeypatch.setattr(usage, "MAX_RECORDS", 2)
        with queue.db:
            usage.prune(queue.db)
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["series"][0]["tokens"] == 1200
        assert queue.db.execute("SELECT sum(calls) FROM usage_rollups").fetchone()[0] == 1
        assert read(cfg)["history_incomplete"]
        assert queue.status()["queue_depth"] == 3
        assert queue.db.execute("SELECT count(*) FROM usage_tokens").fetchone()[0] == 2
        assert queue.db.execute("SELECT count(*) FROM usage_apps").fetchone()[0] == 2
    finally:
        queue.close()
    clock.current += timedelta(days=31)
    queue = ExportQueue(path, usage_scope=usage.identity(cfg))
    queue.close()
    assert read(cfg)["summary"]["calls"] == 0


@pytest.mark.parametrize("zone", ["UTC", "America/Los_Angeles", "Asia/Kathmandu"])
def test_compaction_preserves_periods_breakdowns_replays_and_restarts(tmp_path, clock, monkeypatch, local_timezone, zone):
    clock.current = datetime(2026, 11, 1, 20, 34, 56, tzinfo=timezone.utc)
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    queue = ExportQueue(path, usage_scope=usage.identity(cfg))
    reader = usage.UsageReader()
    packets = []
    with local_timezone(zone):
        try:
            with queue.db:
                queue.db.execute("UPDATE usage_history SET started_at=?", ((clock.current - timedelta(days=40)).timestamp(),))
            for index, days in enumerate((29, 15, 3, 2, 0)):
                when = clock.current - timedelta(days=days, minutes=1)
                packet = body(when, event(str(index), cached_token_count=600, cost_usd=index,
                                         effort="high" if index % 2 else "low"))
                packets.append(packet)
            packets.append(body(clock.current - timedelta(days=2), event("unpriced", model="unknown-model")))
            packets.append(body(clock.current - timedelta(days=3), ("claude_code.api_request", {
                "response_id": "claude", "model": "claude-sonnet-4-6", "input_tokens": 10,
                "output_tokens": 20, "cache_read_tokens": 30, "cost_usd": 5, "effort": "medium"})))
            for packet in packets:
                queue.confirm(queue.append("logs", packet, "application/json", 1))
            before = usage.overview(cfg, 30, reader)
            assert not before["history_incomplete"]
            assert before["summary"]["calls"] == 7
            assert before["summary"]["priced_calls"] == 6
            monkeypatch.setattr(usage, "MAX_RECORDS", 2)
            with queue.db:
                usage.prune(queue.db)
            assert usage.overview(cfg, 30, reader) == usage.overview(cfg, 30) == before
            assert queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 2
            assert queue.db.execute("SELECT sum(calls) FROM usage_rollups").fetchone()[0] == 5
            assert queue.db.execute("SELECT count(*) FROM usage_compacted").fetchone()[0] == 5
            # Native retries and a new enrollment must not recreate compacted calls.
            queue.close()
            queue = ExportQueue(path, usage_scope="new-enrollment")
            for packet in packets:
                queue.confirm(queue.append("logs", packet, "application/json", 1))
            assert usage.overview(cfg, 30, reader) == before
            assert queue.status()["queue_depth"] == 0
        finally:
            reader.close()
            queue.close()


def test_compaction_is_atomic_and_deduplicates_legacy_enrollments(tmp_path, clock, monkeypatch):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    try:
        packet = body(clock.current - timedelta(days=2), event("original"))
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        with queue.db:
            queue.db.execute("INSERT INTO usage_calls SELECT 'copy',event_key,happened_at-3600,model,effort,tokens,cost_usd "
                             "FROM usage_calls")
        before = read(cfg)
        # Remove the earlier-timestamp copy first, retaining the original's counters.
        monkeypatch.setattr(usage, "MAX_RECORDS", 1)
        with queue.db:
            usage.prune(queue.db)
        assert read(cfg) == before
        assert queue.db.execute("SELECT count(*) FROM usage_rollups").fetchone()[0] == 0
        monkeypatch.setattr(usage, "MAX_RECORDS", 0)
        queue.db.execute("CREATE TEMP TRIGGER fail_compaction BEFORE DELETE ON usage_calls "
                         "BEGIN SELECT RAISE(ABORT,'test interruption'); END")
        with pytest.raises(sqlite3.IntegrityError, match="test interruption"), queue.db:
            usage.prune(queue.db)
        assert read(cfg) == before
        assert queue.db.execute("SELECT count(*) FROM usage_compacted").fetchone()[0] == 0
        queue.db.execute("DROP TRIGGER fail_compaction")
        with queue.db:
            usage.prune(queue.db)
        assert read(cfg) == before
        # The trigger also suppresses replay writes from older sensor versions.
        with queue.db:
            queue.db.execute("INSERT INTO usage_calls SELECT 'old-sensor',event_key,happened_at,'unknown','low',999,9 "
                             "FROM usage_compacted")
        assert queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 0
        assert read(cfg) == before
    finally:
        queue.close()


def test_compaction_keeps_exact_24_hours_above_detail_target(tmp_path, clock, monkeypatch):
    clock.current = datetime(2026, 10, 30, 12, 34, 56, tzinfo=timezone.utc)
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    reader = usage.UsageReader()
    try:
        cutoff = clock.current - timedelta(hours=24)
        for index, when in enumerate((cutoff - timedelta(minutes=10), cutoff - timedelta(microseconds=1),
                                      cutoff, cutoff + timedelta(microseconds=1), clock.current - timedelta(seconds=1))):
            queue.confirm(queue.append("logs", body(when, event(str(index), cost_usd=index)), "application/json", 1))
        before = usage.overview(cfg, 1, reader)
        monkeypatch.setattr(usage, "MAX_RECORDS", 1)
        with queue.db:
            usage.prune(queue.db)
        assert queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 4
        assert usage.overview(cfg, 1, reader) == before
        clock.current += timedelta(seconds=1)
        after = usage.overview(cfg, 1, reader)
        assert after["summary"]["calls"] == 1
        assert after["summary"]["cost_usd"] == 4
        assert after["periods"]["30"]["summary"]["calls"] == 5
        clock.current += timedelta(hours=24)
        with queue.db:
            usage.prune(queue.db)
        assert queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 1
        assert usage.overview(cfg, 30, reader)["summary"]["calls"] == 5
    finally:
        reader.close()
        queue.close()


def test_rollups_rebucket_after_timezone_change_and_expire_with_details(tmp_path, clock, monkeypatch, local_timezone):
    clock.current = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    reader = usage.UsageReader()
    try:
        # These straddle Kathmandu's midnight and the first retained local day.
        start = datetime(2026, 10, 2, 18, 15, tzinfo=timezone.utc)
        stamps = [start - timedelta(seconds=1), start, start + timedelta(seconds=1),
                  start + timedelta(days=28), start + timedelta(days=28, seconds=1)]
        # Insert before expiry advances to November's window.
        clock.current -= timedelta(days=1)
        for index, when in enumerate(stamps):
            queue.confirm(queue.append("logs", body(when, event(str(index), cost_usd=index)), "application/json", 1))
        clock.current += timedelta(days=1)
        expected = {}
        for zone in ("UTC", "Asia/Kathmandu", "America/Los_Angeles"):
            with local_timezone(zone):
                expected[zone] = usage.overview(cfg, 30)
        monkeypatch.setattr(usage, "MAX_RECORDS", 0)
        # Kathmandu has the earliest retained midnight of these three zones.
        with local_timezone("Asia/Kathmandu"), queue.db:
            usage.prune(queue.db)
        for zone, before in expected.items():
            with local_timezone(zone):
                assert usage.overview(cfg, 30, reader) == before
        clock.current += timedelta(days=31)
        with queue.db:
            usage.prune(queue.db)
        assert usage.overview(cfg, 30, reader)["summary"]["calls"] == 0
        for table in ("usage_rollups", "usage_compacted", "usage_calls"):
            assert queue.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
    finally:
        reader.close()
        queue.close()


def test_compaction_waits_for_final_imported_message_usage(tmp_path, clock, monkeypatch, history_home):
    when = clock.current - timedelta(days=2)
    write_history(history_home / ".claude/projects/project/session.jsonl", [
        claude_history(when, output=1), claude_history(when + timedelta(seconds=1), ident="second", output=9),
        claude_history(when, output=50),
    ])
    monkeypatch.setattr(usage_import, "BATCH_SIZE", 1)
    reports = []
    for name, cap in (("uncompacted", 100_000), ("compacted", 1)):
        monkeypatch.setattr(usage, "MAX_RECORDS", cap)
        directory = tmp_path / name
        directory.mkdir()
        cfg = config(directory)
        telemetry = Telemetry(cfg)
        try:
            telemetry.accept("logs", body(clock.current - timedelta(seconds=1), event("recent")), "application/json")
            telemetry.import_usage(threading.Event())
            reports.append(read(cfg))
            if cap == 1:
                assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 1
                assert telemetry.queue.db.execute("SELECT sum(calls) FROM usage_rollups").fetchone()[0] == 2
        finally:
            telemetry.close()
    assert reports[0] == reports[1]
    assert reports[1]["summary"]["tokens"] == 1519


def test_rollups_merge_late_calls_without_losing_unknown_or_zero_costs(tmp_path, clock, monkeypatch):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    reader = usage.UsageReader()
    monkeypatch.setattr(usage, "MAX_RECORDS", 0)
    when = (clock.current - timedelta(days=2)).timestamp()
    try:
        # A legacy call has no token details or app identity, and no price.
        with queue.db:
            queue.db.execute("INSERT INTO usage_calls VALUES ('legacy','first',?,'model','low',100,NULL)", (when,))
            queue.db.execute("UPDATE usage_history SET truncated_at=?", (when - 1,))
            usage.prune(queue.db)
        first = usage.overview(cfg, 30, reader)
        assert first["summary"]["cost_usd"] is None
        assert first["summary"]["unclassified_tokens"] == 100
        monkeypatch.setattr(usage, "MAX_RECORDS", 1)
        for key, cost in (("zero", 0), ("paid", 2)):
            with queue.db:
                queue.db.execute("INSERT INTO usage_calls VALUES ('legacy',?,?,'model','low',100,?)", (key, when + 1, cost))
                # Keep a later legacy copy after the original is compacted.
                queue.db.execute("INSERT INTO usage_calls VALUES ('copy',?,?, 'model','low',999,9)", (key, when + 3600))
                usage.prune(queue.db)
            result = usage.overview(cfg, 30, reader)
            assert result == usage.overview(cfg, 30)
            assert result["summary"]["cost_usd"] == cost
        assert result["summary"]["calls"] == 3
        assert result["summary"]["priced_calls"] == 2
        assert result["summary"]["unclassified_tokens"] == result["summary"]["tokens"] == 300
        assert result["history_incomplete"]
        assert queue.db.execute("SELECT count(*) FROM usage_rollups").fetchone()[0] == 1
        monkeypatch.setattr(usage, "MAX_RECORDS", 0)
        with queue.db:
            usage.prune(queue.db)
        assert usage.overview(cfg, 30, reader) == result
    finally:
        reader.close()
        queue.close()


def test_local_bridge_validates_requests_without_server_credentials(tmp_path, monkeypatch, clock):
    cfg = config(tmp_path)
    cfg.pop("sensor_token")
    cfg.save()
    def unexpected_client(_):
        raise AssertionError("local usage must not construct an HTTP client")
    monkeypatch.setattr(bridge, "Client", type("ClientFactory", (), {"from_config": staticmethod(unexpected_client)}))
    for days in (1, 7, 14, 30):
        result = read(cfg, days)
        assert len(result["series"]) == (25 if days == 1 else days)
        assert result["summary"] == dict(calls=0, priced_calls=0, tokens=0, cost_usd=None,
                                         cached_input_tokens=0, uncached_input_tokens=0,
                                         output_tokens=0, unclassified_tokens=0)
    for params in ({"days": value} for value in (True, 0, 13, 15, 31, 365)):
        with pytest.raises(ValueError):
            bridge.handle({"action": "usage.summary", "config_path": str(cfg.path), "params": params})
    with pytest.raises(ValueError):
        bridge.handle({"action": "usage.summary", "config_path": str(cfg.path),
                       "params": {"days": 14, "sensor_id": "other"}})
    assert not (Path(cfg["data_dir"]) / "telemetry.sqlite3").exists()


@pytest.mark.parametrize("requested_days", [1, 14, 30])
def test_plot_periods_share_a_local_snapshot(tmp_path, clock, requested_days):
    cfg = config(tmp_path)
    scope = usage.identity(cfg)
    midnight = clock.current.replace(hour=0)
    start30 = midnight - timedelta(days=29)
    start14 = midnight - timedelta(days=13)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=scope)
    try:
        # Include old ledgers without token details and both sides of each cutoff.
        rows = [
            (scope, "expired", start30.timestamp() - .000001, "old", "low", 1, 9),
            (scope, "oldest", start30.timestamp(), "old", "low", 10, 2),
            (scope, "before14", start14.timestamp() - .000001, "old", "low", 20, None),
            ("former-enrollment", "first14", start14.timestamp(), "recent", "high", 60, 3),
            (scope, "latest", clock.current.timestamp() - .000001, "recent", "high", 90, None),
            (scope, "future", clock.current.timestamp(), "recent", "high", 1, 9),
            ("former-enrollment", "oldest", start30.timestamp(), "old", "low", 10, 2),
        ]
        with queue.db:
            queue.db.executemany("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)", rows)
            queue.db.executemany("INSERT INTO usage_tokens VALUES (?,?,?,?,?)", [
                ("former-enrollment", "first14", 10, 20, 30), (scope, "latest", 20, 30, 40),
            ])
            queue.db.execute("UPDATE usage_history SET started_at=?,truncated_at=? WHERE scope=?",
                             (start30.timestamp() - 1, start14.timestamp() - 1, scope))
            queue.db.execute("INSERT INTO usage_history VALUES (?,?,?)",
                             ("former-enrollment", start14.timestamp() + 1, start30.timestamp() - 1))
        result = read(cfg, requested_days)
        periods = result.pop("periods")
        assert result == periods[str(requested_days)]
        assert set(periods) == {"1", "14", "30"}
        assert periods["1"]["until"] == periods["14"]["until"] == periods["30"]["until"] == clock.current.isoformat()
        assert periods["1"]["summary"]["calls"] == 1
        assert periods["1"]["summary"]["tokens"] == 90
        assert periods["1"]["summary"]["cost_usd"] is None
        assert periods["1"]["summary"]["unclassified_tokens"] == 0
        for days, calls, tokens, cost, unclassified in ((14, 2, 150, 3, 0), (30, 4, 180, 5, 30)):
            period = periods[str(days)]
            assert "periods" not in period
            assert period["days"] == days and len(period["series"]) == days
            assert period["since"] == (start14 if days == 14 else start30).isoformat()
            assert period["summary"] == dict(
                calls=calls, priced_calls=1 if days == 14 else 2, tokens=tokens, cost_usd=cost,
                cached_input_tokens=30, uncached_input_tokens=50, output_tokens=70,
                unclassified_tokens=unclassified,
            )
            assert sum(row["calls"] for row in period["series"]) == calls
            assert period["series"][0]["calls"] == period["series"][-1]["calls"] == 1
            assert {row["name"]: row["calls"] for row in period["by_model"]} == (
                {"recent": 2} if days == 14 else {"recent": 2, "old": 2})
            assert {row["name"]: row["tokens"] for row in period["by_reasoning_effort"]} == (
                {"high": 150} if days == 14 else {"high": 150, "low": 30})
            assert {row["application"] for row in period["breakdown"]} == {"unknown"}
            assert sum(row["calls"] for row in period["breakdown"]) == calls
            assert sum(row["calls"] for day in period["series"] for row in day["breakdown"]) == calls
            assert period["history_incomplete"] is (days == 30)
        assert "periods" not in read(cfg, 7)
    finally:
        queue.close()


@pytest.mark.parametrize(("zone", "now"), [
    ("UTC", "2026-10-07T12:34:56.123456+00:00"),
    ("UTC", "2026-10-07T12:00:00+00:00"),
    ("Asia/Kathmandu", "2026-10-07T20:34:56+00:00"),
    ("America/Los_Angeles", "2026-03-08T20:34:56+00:00"),
    ("America/Los_Angeles", "2026-11-01T20:34:56+00:00"),
])
def test_24_hour_usage_has_exact_cutoffs_and_local_hour_buckets(tmp_path, clock, local_timezone, zone, now):
    clock.current = datetime.fromisoformat(now)
    since = clock.current - timedelta(hours=24)
    with local_timezone(zone):
        first = since.astimezone().replace(minute=0, second=0, microsecond=0).astimezone(timezone.utc)
        boundary = first + timedelta(hours=10)
        stamps = [since - timedelta(microseconds=1), since, boundary - timedelta(microseconds=1),
                  boundary, clock.current - timedelta(microseconds=1), clock.current]
        cfg = config(tmp_path)
        queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
        try:
            for i, stamp in enumerate(stamps):
                attrs = {"model": "unknown-model"} if i == 1 else {"cost_usd": i}
                queue.append("logs", body(stamp, event(str(i), **attrs)), "application/json", 1)
            result = read(cfg, 1)
            assert result["granularity"] == "hour"
            assert result["since"] == since.astimezone().isoformat()
            assert result["until"] == clock.current.astimezone().isoformat()
            assert result["summary"]["calls"] == 4
            assert result["summary"]["priced_calls"] == 3
            assert result["summary"]["cost_usd"] == 9
            assert result["periods"]["30"]["summary"]["calls"] == 5
            series = result["series"]
            assert [row["date"] for row in series] == [
                (first + timedelta(hours=i)).astimezone().isoformat() for i in range(25)]
            for i, row in enumerate(series):
                start = first + timedelta(hours=i)
                assert row["calls"] == sum(start <= stamp < start + timedelta(hours=1) for stamp in stamps[1:-1])
                assert sum(detail["calls"] for detail in row["breakdown"]) == row["calls"]
            for group in (series, result["by_model"], result["by_reasoning_effort"], result["breakdown"]):
                for field in ("calls", "priced_calls", "tokens", "cached_input_tokens", "uncached_input_tokens", "output_tokens"):
                    assert sum(row[field] for row in group) == result["summary"][field]
                assert sum(row["cost_usd"] or 0 for row in group) == 9
        finally:
            queue.close()


@pytest.mark.parametrize(("kind", "attrs", "uncached", "total"), [
    ("codex.sse_event", {"event.kind": "response.completed", "input_token_count": 1000,
                         "cached_token_count": 600, "cache_write_token_count": 100,
                         "output_token_count": 200}, 400, 1200),
    ("claude_code.api_request", {"input_tokens": 1000, "cache_read_tokens": 600,
                                "cache_creation_tokens": 100, "output_tokens": 200}, 1100, 1900),
])
def test_token_breakdowns_match_agent_semantics(tmp_path, clock, kind, attrs, uncached, total):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    try:
        packet = body(clock.current - timedelta(minutes=1), (kind, attrs))
        for _ in range(2):
            ident = queue.append("logs", packet, "application/json", 1)
            queue.confirm(ident)
        result = read(cfg, 7)
        for counts in (result["summary"], result["series"][-1], result["by_model"][0], result["by_reasoning_effort"][0]):
            assert counts["calls"] == 1
            assert counts["cached_input_tokens"] == 600
            assert counts["uncached_input_tokens"] == uncached
            assert counts["output_tokens"] == 200
            assert counts["unclassified_tokens"] == 0
            assert counts["tokens"] == total == 600 + uncached + 200
    finally:
        queue.close()


@pytest.mark.parametrize("has_details_table", [False, True])
def test_upgrade_keeps_old_totals_and_recovers_only_retained_details(tmp_path, clock, has_details_table):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    scope = usage.identity(cfg)
    queue = ExportQueue(path, usage_scope=scope)
    for key in ("delivered", "queued"):
        ident = queue.append("logs", body(clock.current - timedelta(minutes=1), event(key, cached_token_count=600)), "application/json", 1)
        if key == "delivered":
            queue.confirm(ident)
    # Cover both a first upgrade and another upgrade after a rollback.
    with queue.db:
        queue.db.execute("DELETE FROM usage_tokens")
        queue.db.execute("DELETE FROM usage_apps")
        if not has_details_table:
            queue.db.execute("DROP TRIGGER usage_tokens_prune")
            queue.db.execute("DROP TABLE usage_tokens")
            queue.db.execute("DROP TRIGGER usage_apps_prune")
            queue.db.execute("DROP TABLE usage_apps")
        queue.db.execute("UPDATE exports SET usage_projected=1")
    queue.close()
    old = read(cfg)
    assert [(row["application"], row["calls"]) for row in old["breakdown"]] == [("unknown", 2)]
    before = old["summary"]
    assert before["tokens"] == before["unclassified_tokens"] == 2400
    queue = ExportQueue(path, usage_scope=scope)
    try:
        assert queue.next()["batch_id"] == ident
        queue.confirm(ident)
        after = read(cfg)["summary"]
        assert after["tokens"] == before["tokens"]
        assert after["cost_usd"] == before["cost_usd"]
        assert after["cached_input_tokens"] == 600
        assert after["uncached_input_tokens"] == 400
        assert after["output_tokens"] == 200
        assert after["unclassified_tokens"] == 1200
        assert {row["application"]: row["calls"] for row in read(cfg)["breakdown"]} == {"codex": 1, "unknown": 1}
        # Rolling back can still write the original seven-column ledger.
        with queue.db:
            queue.db.execute("INSERT INTO usage_calls VALUES (?,?,?,?,?,?,?)",
                             (scope, "rollback", clock.current.timestamp() - 1, "unknown", "unknown", 10, None))
        assert read(cfg)["summary"]["unclassified_tokens"] == 1210
        assert sum(row["calls"] for row in read(cfg)["breakdown"] if row["application"] == "unknown") == 2
        with queue.db:
            queue.db.execute("DELETE FROM usage_calls")
        assert queue.db.execute("SELECT count(*) FROM usage_tokens").fetchone()[0] == 0
        assert queue.db.execute("SELECT count(*) FROM usage_apps").fetchone()[0] == 0
    finally:
        queue.close()


@pytest.mark.parametrize(("model", "tier", "quote"), [
    ("gpt-6-astra", "ultrafast", .0891),
    ("gpt-6.1-sol", "ultrafast", .01746),
    ("gpt-6-sol", "fast", .00594),
    ("gpt-5.6-sol", "flex", .00297),
    ("gpt-5.6-luna", "priority", .000674),
])
def test_upgrade_recovers_missing_tier_prices_from_retained_exports(tmp_path, clock, model, tier, quote):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    scope = usage.identity(cfg)
    when = clock.current - timedelta(minutes=1)
    attrs = dict(model=model, service_tier=tier, cached_token_count=600, cache_write_token_count=100)
    queue = ExportQueue(path, usage_scope=scope)
    delivered = queue.append("logs", body(when, event("delivered", effort="low", **attrs)), "application/json", 1)
    queue.confirm(delivered)
    ident = queue.append("logs", body(when, event("recover", **attrs),
                         event("preserved", effort="medium", **attrs),
                         event("zero", effort="xhigh", **attrs),
                         event("unknown", service_tier="scale")), "application/json", 4)
    # Emulate the previous snapshot and retain existing quotes, including zero.
    with queue.db:
        queue.db.execute("UPDATE usage_calls SET cost_usd=NULL")
        queue.db.execute("UPDATE usage_calls SET cost_usd=.25 WHERE effort='medium'")
        queue.db.execute("UPDATE usage_calls SET cost_usd=0 WHERE effort='xhigh'")
        queue.db.execute("UPDATE exports SET usage_projected=5")
        queue.db.execute("INSERT INTO usage_calls SELECT 'other',event_key,happened_at,model,effort,tokens,NULL FROM usage_calls")
    queue.close()
    before = read(cfg)["summary"]
    assert before["calls"] == 5 and before["priced_calls"] == 2
    queue = ExportQueue(path, usage_scope=scope)
    try:
        assert queue.next()["batch_id"] == ident
        after = read(cfg)["summary"]
        assert after == {**before, "priced_calls": 3, "cost_usd": pytest.approx(.25 + quote)}
        assert queue.db.execute("SELECT count(cost_usd) FROM usage_calls WHERE scope='other'").fetchone()[0] == 0
        assert queue.next()["batch_id"] == ident
        queue.confirm(ident)
    finally:
        queue.close()
    assert read(cfg)["summary"] == after
    # A redelivery neither doubles usage nor replaces any stored quote.
    queue = ExportQueue(path, usage_scope=scope)
    try:
        ident = queue.append("logs", body(when, event("recover", **attrs)), "application/json", 1)
        queue.confirm(ident)
        assert read(cfg)["summary"] == after
    finally:
        queue.close()


@pytest.mark.parametrize(("table", "change"), [
    ("usage_calls", "model='different-model'"),
    ("usage_calls", "effort='low'"),
    ("usage_calls", "happened_at=happened_at+1"),
    ("usage_calls", "tokens=tokens+1"),
    ("usage_tokens", "cached_input_tokens=599,uncached_input_tokens=401"),
    ("usage_tokens", "output_tokens=201,uncached_input_tokens=399"),
])
def test_price_recovery_rejects_conflicting_usage(tmp_path, clock, table, change):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    packet = body(clock.current - timedelta(minutes=1), event(
        "same-response", service_tier="ultrafast", cached_token_count=600, cache_write_token_count=100,
    ))
    try:
        ident = queue.append("logs", packet, "application/json", 1)
        with queue.db:
            queue.db.execute("UPDATE usage_calls SET cost_usd=NULL")
            queue.db.execute(f"UPDATE {table} SET {change}")
            queue.db.execute("UPDATE exports SET usage_projected=5")
        assert queue.next()["batch_id"] == ident
        queue.confirm(ident)
        # Newly accepted duplicate exports must obey the same recovery checks.
        queue.append("logs", packet, "application/json", 1)
        assert read(cfg)["summary"]["priced_calls"] == 0
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        queue.close()


@pytest.mark.parametrize(("service", "prefix", "label", "projection_version", "application"), [
    ("claude-code", "claude_code.", "eventName", 2, "claude_code"),
    ("claude-code-desktop", "claude_code.", "eventName", 3, "claude_code"),
    ("claude-code-desktop", "", "eventName", 3, "claude_code"),
    ("claude-code-desktop", "", "attribute", 3, "claude_code"),
    ("claude-code-desktop", "", "body", 3, "claude_code"),
    ("cowork", "", "eventName", 4, "cowork"),
    ("cowork", "", "attribute", 4, "cowork"),
    ("cowork", "", "body", 4, "cowork"),
])
def test_app_and_effort_breakdowns_survive_upload_and_reconcile(
    tmp_path, clock, service, prefix, label, projection_version, application,
):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    queue = ExportQueue(path, usage_scope=usage.identity(cfg))
    try:
        # The same model can appear in both apps. Attribute by event, not model.
        when = clock.current - timedelta(minutes=1)
        payload = cost_payload("codex", when, [
            event("codex-high", model="shared-model", cost_usd=4),
            event("codex-low", model="shared-model", effort="low", cost_usd=0),
            event("codex-unpriced", model="shared-model", effort=""),
        ])
        payload["resourceLogs"] += cost_payload(service, when, [
            (prefix + "api_request", {"request_id": "claude-medium", "model": "shared-model",
             "input_tokens": 100, "output_tokens": 20, "effort": "medium", "cost_usd": 6}),
        ], label=label)["resourceLogs"]
        packet = encode_export("logs", payload, "application/json")
        for _ in range(2):
            ident = queue.append("logs", packet, "application/json", 4)
            queue.confirm(ident)
        assert read(cfg)["summary"]["cost_usd"] == 10
        # Recover app details and previously missed app usage from old exports.
        ident = queue.append("logs", packet, "application/json", 4)
        with queue.db:
            queue.db.execute("DELETE FROM usage_apps")
            queue.db.execute("DELETE FROM usage_calls WHERE effort='medium'")
            queue.db.execute("UPDATE exports SET usage_projected=?", (projection_version,))
        assert queue.next()["batch_id"] == ident
        queue.confirm(ident)
    finally:
        queue.close()
    result = read(cfg)
    for period in result["periods"].values():
        groups = period["breakdown"]
        assert {(r["application"], r["model"], r["reasoning_effort"]): r["cost_usd"] for r in groups} == {
            ("codex", "shared-model", "high"): 4,
            ("codex", "shared-model", "low"): 0,
            ("codex", "shared-model", "unknown"): None,
            (application, "shared-model", "medium"): 6,
        }
        assert groups == period["series"][-2 if period["days"] == 1 else -1]["breakdown"]
        assert sum(bool(day["breakdown"]) for day in period["series"]) == 1
        for field in period["summary"]:
            assert sum(r[field] or 0 for r in groups) == period["summary"][field]
        assert period["summary"]["calls"] == 4
        assert period["summary"]["priced_calls"] == 3
    queue = ExportQueue(path)
    try:
        assert queue.status()["queue_depth"] == 0
    finally:
        queue.close()


def test_cowork_requests_do_not_collide_with_code_or_unrelated_services(tmp_path, clock):
    cfg = config(tmp_path)
    packet = {"resourceLogs": []}
    when = clock.current - timedelta(minutes=1)
    for service in ("claude-code-desktop", "cowork", "unrelated"):
        packet["resourceLogs"] += cost_payload(service, when, [
            ("api_request", {"session.id": "same-session", "request_id": "same-request",
             "model": "claude-opus-5-5", "input_tokens": 100, "output_tokens": 20,
             "cache_read_tokens": 60, "cache_creation_tokens": 10, "cost_usd": .01}),
            ("api_error", {"request_id": "failed-request", "cost_usd": 99}),
        ])["resourceLogs"]
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
    try:
        for _ in range(2):
            batch = queue.append("logs", encode_export("logs", packet, "application/json"), "application/json", 6)
            queue.confirm(batch)
        result = read(cfg)
        assert result["summary"]["calls"] == 2
        assert result["summary"]["tokens"] == 380
        assert result["summary"]["cost_usd"] == .02
        assert {row["application"] for row in result["breakdown"]} == {"claude_code", "cowork"}
    finally:
        queue.close()


@pytest.mark.parametrize(("zone", "now", "days"), [
    ("America/Los_Angeles", "2026-10-08T02:23:00+00:00", 14),
    ("Asia/Kathmandu", "2026-10-07T20:00:00+00:00", 30),
    ("America/Los_Angeles", "2026-03-09T19:00:00+00:00", 30),
    ("America/Los_Angeles", "2026-11-02T20:00:00+00:00", 14),
    ("America/Los_Angeles", "2026-11-02T20:00:00+00:00", 7),
])
def test_local_windows_retention_and_clock_changes(tmp_path, clock, local_timezone, zone, now, days):
    clock.current = datetime.fromisoformat(now)
    today = clock.current.astimezone(ZoneInfo(zone)).replace(hour=0, minute=0, second=0, microsecond=0)
    since = today - timedelta(days=days - 1)
    with local_timezone(zone):
        cfg = config(tmp_path)
        queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope=usage.identity(cfg))
        try:
            stamps = [since - timedelta(microseconds=1), since,
                      today - timedelta(microseconds=1), today, clock.current]
            if today.month == 11:
                # Both occurrences of 01:30 belong to yesterday's 25-hour day.
                stamps += [datetime.fromisoformat("2026-11-01T01:30:00-07:00"),
                           datetime.fromisoformat("2026-11-01T01:30:00-08:00")]
            for i, stamp in enumerate(stamps):
                queue.append("logs", body(stamp, event(str(i))), "application/json", 1)
            result = read(cfg, days)
            assert result["since"] == since.isoformat()
            assert result["until"] == clock.current.astimezone(ZoneInfo(zone)).isoformat()
            assert len(result["series"]) == days
            assert result["series"][0]["date"] == since.date().isoformat()
            assert result["series"][-1]["date"] == today.date().isoformat()
            assert result["series"][0]["calls"] == result["series"][-1]["calls"] == 1
            assert result["series"][-2]["calls"] == (3 if today.month == 11 else 1)
            assert result["summary"]["calls"] == len(stamps) - 2
            for period in result.get("periods", {}).values():
                if period["days"] == 1:
                    assert period["since"] == (clock.current - timedelta(hours=24)).astimezone().isoformat()
                    assert period["until"] == result["until"]
                    continue
                start = today - timedelta(days=period["days"] - 1)
                assert period["since"] == start.isoformat()
                assert period["until"] == result["until"]
                assert len(period["series"]) == period["days"]
                assert period["series"][0]["date"] == start.date().isoformat()
                assert period["series"][-2]["calls"] == result["series"][-2]["calls"]
            if days == 30:
                assert queue.db.execute("SELECT min(happened_at) FROM usage_calls").fetchone()[0] == since.timestamp()
        finally:
            queue.close()
