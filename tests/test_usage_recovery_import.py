"""Recover retained request records through the installed sensor import path."""

from datetime import timedelta
import json
import os
from pathlib import Path
import threading

import pytest

from openaidr.sensor import hooks, usage, usage_import, usage_recovery
from openaidr.sensor.telemetry import Telemetry
from test_local_usage import (
    body, claude_history, clock as clock, codex_history, event, history_home as history_home,
    local_timezone as local_timezone, read, write_history,
)
from test_telemetry_sensor import config
from test_telemetry_dashboard import cost_payload
from test_hooks_setup import REAL_CODEX_CONFIG_PATH
from openaidr.core.telemetry import encode_export

REAL_CODEX_PATHS = hooks.codex_paths


def workbuddy_history(when, ident="workbuddy-request", **counts):
    return {"type": "model-usage", "timestamp": int(when.timestamp() * 1000),
            "content": "private-workbuddy-prompt", "output": "private-workbuddy-tool-result",
            "providerData": {"messageId": ident, "conversationRequestId": "private-turn",
                "model": "default-model", "rawUsage": {
                    "prompt_tokens": 1000, "completion_tokens": 50,
                    "cache_read_input_tokens": 200, "cache_creation_input_tokens": 100, **counts},
                "usage": {"inputTokens": 999999}, "secret": "private-workbuddy-secret"}}


def test_workbuddy_recovers_copied_final_and_fallback_records_locally(tmp_path, clock, history_home, monkeypatch):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    record = workbuddy_history(clock.current - timedelta(days=2))
    final = {**record, "type": "reasoning", "id": "different-history-id"}
    paths = [
        write_history(history_home / ".workbuddy/projects/one/session.jsonl", [record, final]),
        write_history(history_home / ".workbuddy-ai/projects/fork/copy.jsonl", [final]),
        write_history(history_home / ".workbuddy-ai/projects/one/parent/subagents/agent-one.jsonl", [
            workbuddy_history(clock.current - timedelta(minutes=1), "subagent-request")]),
    ]
    before = [path.read_bytes() for path in paths]
    telemetry = Telemetry(cfg)
    try:
        for _ in range(2):
            telemetry.import_usage(threading.Event())
        report = read(cfg)
        assert report["summary"] == dict(calls=2, priced_calls=0, tokens=2100, cost_usd=None,
            cached_input_tokens=400, uncached_input_tokens=1600, output_tokens=100, unclassified_tokens=0)
        assert {row["application"] for row in report["breakdown"]} == {"workbuddy"}
        assert report["history_recovery"]["recovered_calls"] == 2
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
        assert not telemetry.queue.db.execute("SELECT 1 FROM usage_imports WHERE application='workbuddy'").fetchone()
        dump = "\n".join(telemetry.queue.db.iterdump())
        assert "private-workbuddy" not in dump and "private-turn" not in dump
        assert [path.read_bytes() for path in paths] == before
        assert not (history_home / ".workbuddy-ai/settings.json").exists()
    finally:
        telemetry.close()


@pytest.mark.parametrize("counts,expected", [
    ({"prompt_tokens": 1000, "completion_tokens": 50, "cache_read_input_tokens": 200,
      "cache_creation_input_tokens": 100}, (1050, 700, 200, 100)),
    ({"input_tokens": 700, "output_tokens": 50, "cache_read_input_tokens": 200,
      "cache_creation_input_tokens": 100}, (1050, 700, 200, 100)),
    ({"prompt_tokens": 1000, "completion_tokens": 50, "prompt_tokens_details": {"cached_tokens": 200},
      "cache_creation_input_tokens": 100}, (1050, 700, 200, 100)),
    ({"prompt_tokens": 1000, "completion_tokens": 50, "prompt_cache_hit_tokens": 200,
      "prompt_cache_miss_tokens": 800}, None),
    ({"prompt_tokens": 1000, "completion_tokens": 50, "cache_read_input_tokens": 0,
      "cache_creation_input_tokens": 0}, (1050, 1000, 0, 0)),
    ({"prompt_tokens": 1000, "completion_tokens": 50}, None),
    ({"credit": 2.5}, None),
    ({"inputTokens": 1000, "outputTokens": 50, "inputTokensDetails": {"cached_tokens": 0}}, None),
    ({"input_tokens": 1000, "output_tokens": 50, "input_tokens_details": {"cached_tokens": 200},
      "cache_read_input_tokens": 200, "cache_creation_input_tokens": 100}, None),
    ({"input_tokens": 700, "output_tokens": True, "cache_read_input_tokens": 200,
      "cache_creation_input_tokens": 100}, None),
    ({"prompt_tokens": 100, "completion_tokens": 50, "cache_read_input_tokens": 200,
      "cache_creation_input_tokens": 100}, None),
    ({"prompt_tokens": 1000, "input_tokens": 700, "completion_tokens": 50,
      "cache_read_input_tokens": 200, "cache_creation_input_tokens": 100}, None),
    ({"prompt_tokens": 1000, "completion_tokens": 50, "cache_read_input_tokens": 200,
      "prompt_tokens_details": {"cached_tokens": 300}, "cache_creation_input_tokens": 100}, None),
])
def test_workbuddy_requires_explicit_consistent_cache_contract(clock, counts, expected):
    record = workbuddy_history(clock.current)
    record["providerData"]["rawUsage"] = counts
    selected = usage_import.READERS["workbuddy"].validate_json(json.dumps(record))
    assert "content" not in selected and "secret" not in selected["providerData"]
    key, item, invalid, _ = usage_import.request_record(selected, "workbuddy", {}, 0, "local-id")
    assert key
    if expected is None:
        assert item is None and invalid == 1
    else:
        assert not invalid and item["usage"]["cost"] is None
        assert tuple(item["usage"][field] for field in (
            "tokens", "input_tokens", "cache_read_tokens", "cache_write_tokens")) == expected


def test_workbuddy_rejects_incomplete_raw_records_and_filters_nested_metadata(clock):
    record = workbuddy_history(clock.current)
    record["providerData"]["rawUsage"]["inputTokensDetails"] = [{"cached_tokens": 0, "secret": "private-nested"}]
    selected = usage_import.READERS["workbuddy"].validate_json(json.dumps(record))
    assert "private-nested" not in json.dumps(selected)
    assert usage_import.request_record(selected, "workbuddy", {}, 0, "local-id")[1] is None
    del record["providerData"]["rawUsage"]["inputTokensDetails"]
    for field in ("usage", "rawUsage", "messageId"):
        incomplete = {**record, "providerData": {key: value for key, value in record["providerData"].items() if key != field}}
        selected = usage_import.READERS["workbuddy"].validate_json(json.dumps(incomplete))
        assert usage_import.request_record(selected, "workbuddy", {}, 0, "local-id")[1] is None


@pytest.mark.parametrize("native_first", [False, True])
def test_workbuddy_native_and_history_share_one_request_key(tmp_path, clock, history_home, monkeypatch, native_first):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    when = clock.current - timedelta(minutes=1)
    path = history_home / ".workbuddy-ai/projects/one/session.jsonl"
    packet = encode_export("logs", cost_payload("workbuddy", when, [("workbuddy.api_request", {
        "request_id": "workbuddy-request", "model": "default-model", "input_tokens": 1000,
        "output_tokens": 50, "cache_read_tokens": 0, "cache_creation_tokens": 0,
    })]), "application/json")
    telemetry = Telemetry(cfg)
    try:
        if native_first:
            telemetry.accept("logs", packet, "application/json")
        write_history(path, [workbuddy_history(when, cache_read_input_tokens=0, cache_creation_input_tokens=0)])
        telemetry.import_usage(threading.Event())
        for _ in range(2):
            telemetry.accept("logs", packet, "application/json")
            telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["tokens"] == 1050
        assert read(cfg)["history_recovery"]["recovered_calls"] == 0
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_recovered").fetchone()[0] == 0
    finally:
        telemetry.close()


def test_workbuddy_partial_tail_reset_override_and_protected_paths(tmp_path, clock, history_home, monkeypatch):
    root = history_home / "custom-workbuddy"
    monkeypatch.setenv("WORKBUDDY_CONFIG_DIR", str(root))
    cfg = config(tmp_path)
    when = clock.current - timedelta(minutes=1)
    path = write_history(root / "projects/one/session.jsonl", [])
    write_history(history_home / ".workbuddy-ai/projects/one/ignored.jsonl", [workbuddy_history(when, "ignored")])
    outside = write_history(history_home / "Documents/private.jsonl", [workbuddy_history(when, "protected")])
    path.with_name("escape.jsonl").symlink_to(outside)
    serialized = json.dumps(workbuddy_history(when, completion_tokens=1))
    path.write_text(serialized[:30])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 0
        with path.open("a") as stream:
            stream.write(serialized[30:] + "\n")
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["tokens"] == 1001
        with path.open("a") as stream:
            stream.write(json.dumps(workbuddy_history(when)) + "\n")
            stream.write(serialized + "\n")  # Smaller copied/retried update cannot replace final usage.
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["tokens"] == 1050
        original = Path.open
        with monkeypatch.context() as patch:
            def unchanged(self, *args, **kwargs):
                assert self not in (path, outside), "unchanged or protected source must not be read"
                return original(self, *args, **kwargs)
            patch.setattr(Path, "open", unchanged)
            telemetry.import_usage(threading.Event())
        write_history(path, [workbuddy_history(when, "replacement")])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert usage_import.recovery_status(telemetry.queue.db)["inaccessible_sources"] >= 1
    finally:
        telemetry.close()


def test_workbuddy_lossy_native_report_cannot_replace_recovered_cache_counts(tmp_path, clock, history_home, monkeypatch):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    when = clock.current - timedelta(minutes=1)
    write_history(history_home / ".workbuddy/projects/one/session.jsonl", [workbuddy_history(when)])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        before = read(cfg)["summary"]
        packet = encode_export("logs", cost_payload("workbuddy", when, [("workbuddy.api_request", {
            "request_id": "workbuddy-request", "model": "default-model", "input_tokens": 1000,
            "output_tokens": 50, "workbuddy.usage.unavailable": "cache_breakdown", "credit": 5,
        })]), "application/json")
        telemetry.accept("logs", packet, "application/json")
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"] == before
        assert read(cfg)["history_recovery"]["recovered_calls"] == 1
    finally:
        telemetry.close()


@pytest.mark.parametrize("mode", ["disabled", "stopped", "paused"])
def test_workbuddy_recovery_honors_collection_optouts(tmp_path, clock, history_home, monkeypatch, mode):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    path = write_history(history_home / ".workbuddy/projects/one/session.jsonl", [workbuddy_history(clock.current)])
    telemetry = Telemetry(cfg)
    try:
        if mode == "disabled":
            cfg["telemetry"]["enabled"] = False
        stop = threading.Event()
        if mode == "stopped":
            stop.set()
        assert not usage_import.requests_once(cfg, telemetry.queue, stop, lambda: mode == "paused")
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_calls").fetchone()[0] == 0
        assert path.exists()
    finally:
        telemetry.close()


def test_workbuddy_unknown_native_identity_blocks_recovery(tmp_path, clock, history_home, monkeypatch):
    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    record = workbuddy_history(clock.current - timedelta(minutes=1))
    write_history(history_home / ".workbuddy/projects/one/session.jsonl", [record])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["history_recovery"]["recovered_calls"] == 1
        _, native, _, _ = usage_import.request_record(record, "workbuddy", {}, 0, telemetry.queue.usage_scope)
        native.update(key="unmatched-native", attributes={})
        with telemetry.queue.lock, telemetry.queue.db:
            usage_recovery.native(telemetry.queue.db, telemetry.queue.usage_scope, [native])
            usage.record_calls(telemetry.queue.db, telemetry.queue.usage_scope, [native])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["history_recovery"]["recovered_calls"] == 0
        assert not usage_recovery.allowed(telemetry.queue.db, "workbuddy")
    finally:
        telemetry.close()


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("replacement", ["protected", pytest.param("fifo", marks=pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFO files are unavailable on this platform"))])
def test_workbuddy_guards_replaced_files_before_probes_and_open(tmp_path, clock, history_home, monkeypatch, replay, replacement):
    from openaidr.sensor.privacy import PrivacyGuard, PrivacySkip

    monkeypatch.delenv("WORKBUDDY_CONFIG_DIR", raising=False)
    cfg = config(tmp_path)
    record = workbuddy_history(clock.current - timedelta(minutes=1))
    path = write_history(history_home / ".workbuddy/projects/one/session.jsonl", [record])
    target = write_history(history_home / "Documents/private.jsonl", [workbuddy_history(clock.current, "private")])
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        if replay:
            with telemetry.queue.db:
                telemetry.queue.db.execute("UPDATE usage_request_files SET blocked=1 WHERE application='workbuddy'")
                telemetry.queue.db.execute("UPDATE usage_sources SET kind='native_unknown' WHERE application='workbuddy'")
            assert not usage_recovery.allowed(telemetry.queue.db, "workbuddy")
        path.unlink()
        if replacement == "protected":
            path.symlink_to(target)
        else:
            os.mkfifo(path)
            if replay:
                # Initial traversal skips this old entry; saved-file replay must
                # independently reject its type after the proof enables recovery.
                os.utime(path, (0, 0))
        path.with_name("directory-loop").symlink_to(path.parent, target_is_directory=True)
        write_history(path.with_name("proof.jsonl"), [record])
        check, stat, scandir, open_file = PrivacyGuard.check, Path.stat, os.scandir, Path.open

        def guarded(self, candidate):
            if replacement == "protected" and Path(candidate) == path:
                raise PrivacySkip("protected test target")
            return check(self, candidate)

        def no_following_stat(self, *args, **kwargs):
            assert replacement != "protected" or self not in (path, target), "protected replay target stat before privacy guard"
            return stat(self, *args, **kwargs)

        def no_replacement_open(self, *args, **kwargs):
            assert self not in (path, target), "protected or nonregular source must not be opened"
            return open_file(self, *args, **kwargs)

        class Entry:
            def __init__(self, entry):
                self.entry = entry

            def __getattr__(self, name):
                return getattr(self.entry, name)

            def is_dir(self, *, follow_symlinks=True):
                if replacement == "protected" and Path(self.path) == path and follow_symlinks:
                    # Let the second case reach replay independently of os.walk's bug.
                    assert replay, "protected initial target classified before privacy guard"
                    return False
                return self.entry.is_dir(follow_symlinks=follow_symlinks)

            def stat(self, *, follow_symlinks=True):
                assert replacement != "protected" or Path(self.path) != path or not follow_symlinks, "protected target stat before privacy guard"
                return self.entry.stat(follow_symlinks=follow_symlinks)

            def is_file(self, *, follow_symlinks=True):
                assert replacement != "protected" or Path(self.path) != path or not follow_symlinks, "protected target classified before privacy guard"
                return self.entry.is_file(follow_symlinks=follow_symlinks)

        class Entries:
            def __init__(self, directory):
                self.iterator = scandir(directory)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.iterator.close()

            def __iter__(self):
                return self

            def __next__(self):
                return Entry(next(self.iterator))

        monkeypatch.setattr(PrivacyGuard, "check", guarded)
        monkeypatch.setattr(Path, "stat", no_following_stat)
        monkeypatch.setattr(Path, "open", no_replacement_open)
        monkeypatch.setattr(os, "scandir", Entries)
        assert usage_import.requests_once(cfg, telemetry.queue, threading.Event())
        assert usage_recovery.allowed(telemetry.queue.db, "workbuddy")
        row = telemetry.queue.db.execute("SELECT inaccessible FROM usage_request_files WHERE path=?", (str(path),)).fetchone()
        assert row[0] == 1
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        telemetry.close()


def request_record(when, ident="response-one"):
    return {"type": "token_usage_record", "timestamp": when.isoformat(), "payload": {
        "thread_id": "thread-one", "turn_id": "turn-one", "response_id": ident,
        "usage": {"input_tokens": 1000, "cached_input_tokens": 600,
                  "cache_write_input_tokens": 0, "output_tokens": 200},
    }}


def context():
    return {"type": "turn_context", "payload": {
        "turn_id": "turn-one", "model": "gpt-6.1-sol", "effort": "high",
    }}


@pytest.mark.parametrize("shared_config", [False, True])
@pytest.mark.parametrize("record_format", ["legacy", "request"])
def test_codex_profiles_import_separate_history_with_shared_settings(
        tmp_path, clock, history_home, monkeypatch, shared_config, record_format):
    monkeypatch.setattr(hooks, "codex_paths", REAL_CODEX_PATHS)
    monkeypatch.setattr(hooks, "codex_config_path", REAL_CODEX_CONFIG_PATH)
    cfg = config(tmp_path)
    profiles = [history_home / name for name in (".codex", ".codex-account2", ".codex-account3")]

    def records(ident):
        if record_format == "request":
            return [context(), request_record(clock.current - timedelta(days=2), ident)]
        rows = codex_history(clock)
        rows[0]["payload"]["id"] = "session-" + ident
        rows[1]["payload"]["turn_id"] = "turn-" + ident
        return rows

    profiles[0].mkdir()
    (profiles[0] / "config.toml").write_text('model = "gpt-6.1-sol"\n')
    telemetry = Telemetry(cfg)
    try:
        if record_format == "request":
            telemetry.import_usage(threading.Event())
            clock.current += timedelta(days=3)
        original = records("one")
        write_history(profiles[0] / "sessions/one.jsonl", original)
        telemetry.import_usage(threading.Event())
        before = read(cfg)["summary"]
        assert before["calls"] == (1 if record_format == "request" else 2)
        cutoff = telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='codex'").fetchone()[0]
        for profile, directory in zip(profiles[1:], ("sessions", "archived_sessions")):
            write_history(profile / directory / "own.jsonl", records(profile.name))
            if shared_config:
                (profile / "config.toml").symlink_to(profiles[0] / "config.toml")
            else:
                (profile / "config.toml").write_text('model = "gpt-6.1-sol"\n')
        write_history(profiles[1] / "archived_sessions/copy.jsonl", original)
        (history_home / ".codex-alias").symlink_to(profiles[1], target_is_directory=True)
        write_history(history_home / ".codexbar/sessions/ignored.jsonl", records("ignored"))

        for _ in range(2):
            telemetry.import_usage(threading.Event())
            after = read(cfg)["summary"]
            assert after["calls"] == before["calls"] * 3
            assert after["tokens"] == before["tokens"] * 3
            assert after["cost_usd"] == pytest.approx(before["cost_usd"] * 3)
        assert usage_import.roots(cfg, "codex") == sorted(
            profile / directory for profile in profiles for directory in ("sessions", "archived_sessions"))
        assert telemetry.queue.db.execute("SELECT cutoff FROM usage_imports WHERE application='codex'").fetchone()[0] == cutoff
        assert telemetry.queue.db.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
    finally:
        telemetry.close()


def test_upgrade_recovers_request_after_completed_history_cutoff(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 0
        clock.current += timedelta(hours=2)
        write_history(history_home / ".codex/sessions/recovered.jsonl", [
            context(), request_record(clock.current - timedelta(minutes=1)),
        ])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["tokens"] == 1200
        assert read(cfg)["history_recovery"]["recovered_calls"] == 1
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        telemetry.close()


@pytest.mark.parametrize("native_first", [False, True])
def test_exact_request_native_overlap_preserves_reported_cost(tmp_path, clock, history_home, native_first):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        when = clock.current - timedelta(minutes=1)
        packet = body(when, event("response-one", cached_token_count=600, cost_usd=.5))
        if native_first:
            telemetry.accept("logs", packet, "application/json")
        write_history(history_home / ".codex/sessions/one.jsonl", [context(), request_record(when)])
        telemetry.import_usage(threading.Event())
        if not native_first:
            telemetry.accept("logs", packet, "application/json")
        result = read(cfg)["summary"]
        assert result["calls"] == 1 and result["tokens"] == 1200
        assert result["cost_usd"] == .5
        assert read(cfg)["history_recovery"]["recovered_calls"] == 0
        assert telemetry.queue.db.execute("SELECT count(*) FROM usage_recovered").fetchone()[0] == 0
    finally:
        telemetry.close()


def test_copied_requests_and_appended_claude_final_usage_are_counted_once(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        when = clock.current - timedelta(minutes=1)
        rows = [context(), request_record(when)]
        write_history(history_home / ".codex/sessions/one.jsonl", rows)
        write_history(history_home / ".codex/archived_sessions/copy.jsonl", rows)
        partial = {**claude_history(when, output=1), "requestId": "claude-request"}
        path = write_history(history_home / ".claude/projects/one/session.jsonl", [partial])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["summary"]["tokens"] == 1331
        with path.open("a") as stream:
            stream.write(json.dumps({**claude_history(when), "requestId": "claude-request"}) + "\n")
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["summary"]["tokens"] == 1360
        assert "private-history-sentinel" not in "\n".join(telemetry.queue.db.iterdump())
    finally:
        telemetry.close()


def test_watch_recovers_complete_append_and_defers_partial_line(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        path = write_history(history_home / ".codex/sessions/one.jsonl", [context()])
        serialized = json.dumps(request_record(clock.current - timedelta(minutes=1)))
        seen = []

        class Stop:
            polls = 0

            def is_set(self):
                return self.polls == 3

            def wait(self, _):
                seen.append(read(cfg)["summary"]["calls"])
                self.polls += 1
                if self.polls < 3:
                    with path.open("a") as stream:
                        stream.write(serialized[:30] if self.polls == 1 else serialized[30:] + "\n")

        telemetry.import_usage(Stop(), watch=True)
        assert seen == [0, 0, 1]
        assert usage_import.recovery_status(telemetry.queue.db)["pending_files"] == 0
    finally:
        telemetry.close()


def test_unchanged_files_are_not_read_again_and_truncated_file_replays(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        path = write_history(history_home / ".codex/sessions/one.jsonl", [
            context(), request_record(clock.current - timedelta(minutes=1)),
        ])
        telemetry.import_usage(threading.Event())
        original = Path.open
        relative_to = Path.is_relative_to
        boundary_checks = []
        with monkeypatch.context() as patch:
            def unchanged(self, *args, **kwargs):
                assert self != path, "unchanged transcript must not be read"
                return original(self, *args, **kwargs)
            def boundary(self, *args):
                if self == path:
                    boundary_checks.append(1)
                return relative_to(self, *args)
            patch.setattr(Path, "open", unchanged)
            patch.setattr(Path, "is_relative_to", boundary)
            assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
            checked = len(boundary_checks)
            assert checked
            assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
            assert len(boundary_checks) == checked, "unchanged roots must reuse lexical path checks"
        write_history(path, [context(), request_record(clock.current - timedelta(seconds=1), "new")])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
    finally:
        telemetry.close()


def test_import_revision_revisits_missing_prices_without_changing_native_cost(tmp_path, clock, history_home, monkeypatch):
    from openaidr.core import hook_estimates

    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        row = {**claude_history(clock.current - timedelta(minutes=1)), "requestId": "fable"}
        row["message"]["model"] = "claude-fable-5-1"
        write_history(history_home / ".claude/projects/one/session.jsonl", [row])
        with monkeypatch.context() as old:
            old.delitem(hook_estimates.RATES, "claude-fable-5-1")
            telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["priced_calls"] == 0
        monkeypatch.setattr(usage_import, "IMPORT_VERSION", usage_import.IMPORT_VERSION + 1)
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["cost_usd"] == pytest.approx(.002025)
    finally:
        telemetry.close()


def test_interrupted_recovery_replays_uncommitted_cursor_without_duplicates(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        write_history(history_home / ".codex/sessions/one.jsonl", [context(),
            request_record(clock.current - timedelta(minutes=2), "one"),
            request_record(clock.current - timedelta(minutes=1), "two"),
        ])
        original = usage_recovery.recover
        calls = []
        with monkeypatch.context() as interrupted:
            interrupted.setattr(usage_import, "BATCH_SIZE", 1)
            def fail_second(*args):
                calls.append(1)
                if len(calls) == 2:
                    raise OSError("interrupted")
                return original(*args)
            interrupted.setattr(usage_recovery, "recover", fail_second)
            with pytest.raises(OSError, match="interrupted"):
                usage_import.run_once(cfg, telemetry.queue, threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
    finally:
        telemetry.close()


@pytest.mark.parametrize("stopping", [False, True])
@pytest.mark.parametrize("rescan", [False, True])
def test_request_scan_interruption_remains_retryable(tmp_path, clock, history_home, monkeypatch, stopping, rescan):
    cfg, stop = config(tmp_path), threading.Event()
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        path = write_history(history_home / ".codex/sessions/one.jsonl", [context(),
            request_record(clock.current - timedelta(minutes=2), "one"),
            request_record(clock.current - timedelta(minutes=1), "two")])
        if rescan:
            assert usage_import.requests_once(cfg, telemetry.queue, stop)
            with telemetry.queue.db:
                telemetry.queue.db.execute("UPDATE usage_request_files SET blocked=1")
                telemetry.queue.db.execute("UPDATE usage_sources SET kind='native_unknown'")
            write_history(path.with_name("proof.jsonl"), [context(), request_record(clock.current, "one"), request_record(clock.current, "two")])
        before = [tuple(row) for row in telemetry.queue.db.execute("SELECT * FROM usage_request_files")]
        opened, original = [], Path.open
        def open_file(file, *args, **kwargs):
            stream = original(file, *args, **kwargs)
            if file == path:
                opened.append(stream)
            return stream
        def paused():
            interrupted = any(not stream.closed and stream.tell() > 0 for stream in opened)
            if interrupted and stopping:
                stop.set()
            return interrupted and not stopping
        with monkeypatch.context() as interrupted:
            interrupted.setattr(Path, "open", open_file)
            assert not usage_import.requests_once(cfg, telemetry.queue, stop, paused)
        assert [tuple(row) for row in telemetry.queue.db.execute("SELECT * FROM usage_request_files")] == before
        assert usage_import.recovery_status(telemetry.queue.db)["inaccessible_files"] == 0
        assert usage_import.requests_once(cfg, telemetry.queue, threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
    finally:
        telemetry.close()


def test_invalid_unmatched_and_missing_sources_remain_visible(tmp_path, clock, history_home):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        path = write_history(history_home / ".claude/projects/one/session.jsonl", [claude_history(clock.current)])
        with path.open("a") as stream:
            stream.write(json.dumps({"type": "assistant", "requestId": "zero", "timestamp": clock.current.isoformat(),
                                    "message": {"id": "zero", "usage": {"input_tokens": 0, "output_tokens": 0}}}) + "\n")
            stream.write("invalid JSON\npartial")
        telemetry.import_usage(threading.Event())
        status = usage_import.recovery_status(telemetry.queue.db)
        assert status["unsupported_records"] == 1
        assert status["invalid_records"] == 1
        assert status["pending_files"] == 1
        telemetry.import_usage(threading.Event())
        assert usage_import.recovery_status(telemetry.queue.db) == status
        path.unlink()
        telemetry.import_usage(threading.Event())
        assert usage_import.recovery_status(telemetry.queue.db)["inaccessible_files"] == 1
        cfg["hooks"] = {"homes": {"codex": str(history_home / "missing-profile")}}
        telemetry.import_usage(threading.Event())
        assert usage_import.recovery_status(telemetry.queue.db)["inaccessible_sources"] == 1
        cfg["hooks"]["homes"]["claude"] = str(history_home / "other-claude")
        telemetry.import_usage(threading.Event())
        assert usage_import.recovery_status(telemetry.queue.db)["inaccessible_files"] == 0
        assert not telemetry.queue.db.execute("SELECT 1 FROM usage_request_files WHERE path=?", (str(path),)).fetchone()
    finally:
        telemetry.close()


@pytest.mark.parametrize("modern_first", [True, False])
def test_exact_source_link_handles_split_cutoff_and_late_native(tmp_path, clock, history_home, modern_first):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        shift = timedelta(milliseconds=1)
        modern_at = clock.current - shift if modern_first else clock.current + shift
        legacy_at = clock.current + shift if modern_first else clock.current - shift
        modern = request_record(modern_at)
        modern["payload"]["thread_token_usage"] = modern["payload"]["usage"]
        legacy = {"type": "event_msg", "timestamp": legacy_at.isoformat(), "payload": {
            "type": "token_count", "info": {"total_token_usage": modern["payload"]["usage"],
                                             "last_token_usage": modern["payload"]["usage"]},
        }}
        write_history(history_home / ".codex/sessions/boundary.jsonl", [context(), modern, legacy])
        telemetry.import_usage(threading.Event())
        clock.current += timedelta(seconds=1)
        assert read(cfg)["summary"]["calls"] == 1
        telemetry.accept("logs", body(modern_at, event("response-one", cached_token_count=600, cost_usd=.5)), "application/json")
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["summary"]["cost_usd"] == .5
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        telemetry.close()


@pytest.mark.parametrize("keep_profile", [True, False])
def test_blocker_expiry_replays_retained_selected_profiles_only(tmp_path, clock, history_home, monkeypatch, keep_profile):
    cfg = config(tmp_path)
    profile = history_home / "account-three"
    cfg["hooks"] = {"homes": {"codex": str(profile)}}
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        unknown_at = clock.current + timedelta(hours=1)
        clock.current += timedelta(days=29)
        path = write_history(profile / "sessions/one.jsonl", [context(), request_record(clock.current - timedelta(days=2))])
        telemetry.import_usage(threading.Event())
        unknown = event("unknown")
        del unknown[1]["response_id"]
        telemetry.accept("logs", body(unknown_at, unknown), "application/json")
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert usage_import.recovery_status(telemetry.queue.db)["blocked_files"] == 1
        original = Path.open
        def forbidden(self, *args, **kwargs):
            assert self != path, "unchanged blocked or retired profile must not be read"
            return original(self, *args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(Path, "open", forbidden)
            telemetry.import_usage(threading.Event())
        if not keep_profile:
            cfg["hooks"] = {"homes": {"codex": str(history_home / "replacement")}}
        clock.current += timedelta(days=2)
        with monkeypatch.context() as patch:
            if not keep_profile:
                patch.setattr(Path, "open", forbidden)
            telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == int(keep_profile)
        assert usage_import.recovery_status(telemetry.queue.db)["blocked_files"] == 0
    finally:
        telemetry.close()


def test_legacy_alias_can_reprice_while_unknown_native_blocks_new_recovery(tmp_path, clock, history_home, monkeypatch):
    from openaidr.core import hook_estimates

    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        row = {**claude_history(clock.current - timedelta(hours=1)), "requestId": "legacy-fable"}
        row["message"]["model"] = "claude-fable-5-1"
        write_history(history_home / ".claude/projects/one/session.jsonl", [row])
        with monkeypatch.context() as old:
            old.delitem(hook_estimates.RATES, "claude-fable-5-1")
            telemetry.import_usage(threading.Event())
        clock.current += timedelta(hours=1)
        unknown = ("claude_code.api_request", {"input_tokens": 1, "output_tokens": 1})
        telemetry.accept("logs", body(clock.current - timedelta(minutes=1), unknown), "application/json")
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["summary"]["priced_calls"] == 0
        monkeypatch.setattr(usage_import, "IMPORT_VERSION", usage_import.IMPORT_VERSION + 1)
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 2
        assert read(cfg)["summary"]["priced_calls"] == 1
        assert read(cfg)["summary"]["cost_usd"] == pytest.approx(.002025)
    finally:
        telemetry.close()


@pytest.mark.parametrize("compacted", [False, True])
@pytest.mark.parametrize("coalesced", [False, True])
@pytest.mark.parametrize("legacy_before", [False, True])
def test_legacy_alias_preserves_compacted_and_coalesced_boundary_usage(tmp_path, clock, history_home, compacted, coalesced, legacy_before):
    from openaidr.sensor import usage

    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        direction = 1 if legacy_before else -1
        modern = request_record(clock.current + timedelta(milliseconds=direction))
        modern["payload"]["thread_token_usage"] = modern["payload"]["usage"]
        rows = [context(), modern]
        total = modern["payload"]["usage"]
        if coalesced:
            second = request_record(clock.current + timedelta(milliseconds=2 * direction), "response-two")
            total = {key: value * 2 for key, value in total.items()}
            second["payload"]["thread_token_usage"] = total
            rows.append(second)
        rows.append({"type": "event_msg", "timestamp": (clock.current - timedelta(milliseconds=direction)).isoformat(),
                     "payload": {"type": "token_count", "info": {"total_token_usage": total, "last_token_usage": total}}})
        path = write_history(history_home / ".codex/sessions/one.jsonl", rows)
        assert usage_import.history_once(cfg, telemetry.queue, threading.Event())
        if compacted:
            with telemetry.queue.db:
                usage._compact(telemetry.queue.db, clock.current.timestamp(), 1)
        assert usage_import.requests_once(cfg, telemetry.queue, threading.Event())
        clock.current += timedelta(seconds=1)
        supported = legacy_before or not coalesced
        assert read(cfg)["summary"]["calls"] == int(supported)
        assert read(cfg)["summary"]["tokens"] == ((2400 if coalesced else 1200) if supported else 0)
        status = usage_import.recovery_status(telemetry.queue.db)
        assert bool(status["unreconciled_records"]) == (legacy_before and (compacted or coalesced))
        assert status["unsupported_records"] == int(not supported)
        # A later legacy-only turn must remain visibly unsupported.
        with path.open("a") as stream:
            stream.write(json.dumps({**context(), "payload": {**context()["payload"], "turn_id": "later"}}) + "\n")
            stream.write(json.dumps({"type": "event_msg", "timestamp": clock.current.isoformat(), "payload": {
                "type": "token_count", "info": {"total_token_usage": {key: value * 2 for key, value in total.items()}}}}) + "\n")
        telemetry.import_usage(threading.Event())
        assert usage_import.recovery_status(telemetry.queue.db)["unsupported_records"] == 1 + int(not supported)
    finally:
        telemetry.close()


def test_unreadable_legacy_source_does_not_block_another_application(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        clock.current += timedelta(hours=1)
        path = write_history(history_home / ".codex/sessions/unreadable.jsonl", [context()])
        write_history(history_home / ".claude/projects/one/session.jsonl", [
            {**claude_history(clock.current - timedelta(minutes=1)), "requestId": "readable"}])
        original = usage_import.records
        def unreadable(source, *args):
            if source == path:
                raise PermissionError("unreadable history")
            return original(source, *args)
        monkeypatch.setattr(usage_import, "records", unreadable)
        assert not usage_import.run_once(cfg, telemetry.queue, threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["history_recovery"]["inaccessible_sources"] == 1
    finally:
        telemetry.close()


def test_later_legacy_link_protects_existing_recovery_from_unknown_native(tmp_path, clock, history_home, monkeypatch):
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    try:
        telemetry.import_usage(threading.Event())
        cutoff = clock.current
        clock.current += timedelta(hours=1)
        modern = request_record(clock.current - timedelta(minutes=1))
        modern["payload"]["thread_token_usage"] = modern["payload"]["usage"]
        write_history(history_home / ".codex/sessions/modern.jsonl", [context(), modern])
        telemetry.import_usage(threading.Event())
        assert read(cfg)["history_recovery"]["recovered_calls"] == 1
        write_history(history_home / ".codex/archived_sessions/legacy.jsonl", [context(), modern, {
            "type": "event_msg", "timestamp": (cutoff - timedelta(milliseconds=1)).isoformat(), "payload": {
                "type": "token_count", "info": {"total_token_usage": modern["payload"]["usage"],
                                                 "last_token_usage": modern["payload"]["usage"]}}}])
        monkeypatch.setattr(usage_import, "IMPORT_VERSION", usage_import.IMPORT_VERSION + 1)
        telemetry.import_usage(threading.Event())
        assert read(cfg)["summary"]["calls"] == 1
        assert read(cfg)["history_recovery"]["recovered_calls"] == 0
        unknown = event("unknown", input_token_count=1, output_token_count=1)
        del unknown[1]["response_id"]
        telemetry.accept("logs", body(clock.current - timedelta(seconds=1), unknown), "application/json")
        assert read(cfg)["summary"]["tokens"] == 1202
    finally:
        telemetry.close()


@pytest.mark.parametrize("reprice", [False, True])
def test_legacy_request_upgrade_work_scales_with_retained_history(tmp_path, clock, history_home, monkeypatch, reprice):
    from openaidr.core import hook_estimates

    work = []
    for count in (250, 500):
        cfg = config(tmp_path / str(count))
        telemetry = Telemetry(cfg)
        try:
            write_history(history_home / ".claude/projects/one/session.jsonl", [
                {**claude_history(clock.current - timedelta(hours=1), ident=f"message-{index}"), "requestId": f"request-{index}"}
                for index in range(count)])
            with monkeypatch.context() as initial:
                if reprice:
                    initial.delitem(hook_estimates.RATES, "claude-sonnet-4-6")
                assert usage_import.history_once(cfg, telemetry.queue, threading.Event())
                if reprice:
                    assert usage_import.requests_once(cfg, telemetry.queue, threading.Event())
            steps = []
            telemetry.queue.db.set_progress_handler(lambda: steps.append(1) or 0, 1000)
            with monkeypatch.context() as upgrade:
                if reprice:
                    upgrade.setattr(usage_import, "IMPORT_VERSION", usage_import.IMPORT_VERSION + 1)
                assert usage_import.run_once(cfg, telemetry.queue, threading.Event())
            telemetry.queue.db.set_progress_handler(None, 0)
            assert read(cfg)["summary"]["calls"] == count
            work.append(len(steps))
        finally:
            telemetry.close()
    assert work[1] < work[0] * 3, f"Doubling retained history must not quadruple database work: {work}"


@pytest.mark.parametrize("operation", ["metrics", "unknown_native", "history"])
def test_usage_maintenance_work_does_not_scale_with_unexpired_metadata(tmp_path, clock, history_home, operation):
    from openaidr.sensor import usage_recovery_aliases

    work = []
    when = (clock.current - timedelta(days=2)).timestamp()
    expired = (clock.current - timedelta(days=35)).timestamp()
    for count in (250, 2500):
        cfg = config(tmp_path / str(count))
        telemetry = Telemetry(cfg)
        db = telemetry.queue.db
        try:
            with db:
                usage_recovery_aliases.initialize(db)
                keys = [(f"legacy-{index}", when) for index in range(count)] + [("expired", expired)]
                db.executemany("INSERT INTO usage_sources VALUES (?,'codex','legacy',?)", keys)
                db.executemany("INSERT INTO usage_recovered VALUES (?,'codex',?,'gpt-6.1-sol','high',1200,0,1000,200,.5,'')", keys)
                db.executemany("INSERT INTO usage_request_aliases VALUES (?,?,?,1)", [
                    (key, "history:" + key, stamp) for key, stamp in keys])
                # Keep the history admission checks independent of the size of
                # retained metadata; this test measures expiry and withdrawal.
                for app in ("codex", "claude_code", "workbuddy"):
                    db.execute("INSERT INTO usage_sources VALUES (?,?,'native_unknown',?)", ("unknown-" + app, app, when))
                    db.execute("INSERT INTO usage_imports VALUES (?,?,?,1)", (telemetry.queue.usage_scope, app, when))
            steps = []
            db.set_progress_handler(lambda: steps.append(1) or 0, 100)
            try:
                if operation == "history":
                    assert usage_import.requests_once(cfg, telemetry.queue, threading.Event())
                elif operation == "metrics":
                    telemetry.queue.confirm(telemetry.queue.append("metrics", b"{}", "application/json", 0))
                else:
                    unknown = event("unknown", input_token_count=1, output_token_count=1)
                    del unknown[1]["response_id"]
                    telemetry.accept("logs", body(clock.current - timedelta(seconds=1), unknown), "application/json")
            finally:
                db.set_progress_handler(None, 0)
            work.append(len(steps))
            assert db.execute("SELECT count(*) FROM usage_recovered").fetchone()[0] == count
            assert not db.execute("SELECT 1 FROM usage_sources WHERE event_key='expired'").fetchone()
            if operation == "history":
                assert db.execute("SELECT count(*) FROM usage_request_aliases").fetchone()[0] == count
        finally:
            telemetry.close()
    assert work[1] < max(work[0] * 3, 30), f"Ten times the retained metadata must not require a full scan: {work}"
