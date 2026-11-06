"""Exact-request history reconciliation through the real local accounting queue."""

from datetime import timedelta
from pathlib import Path

import pytest

from openaidr.core.agent_usage import extract
from openaidr.core.telemetry import decode_export, encode_export
from openaidr.sensor import usage, usage_recovery
from openaidr.sensor.telemetry import ExportQueue
from test_local_usage import body, clock, event, local_timezone, read
from test_telemetry_sensor import config
from test_telemetry_dashboard import cost_payload


def history(clock, ident, when=None, **attrs):
    when = when or clock.current - timedelta(days=2)
    return next(extract(dict(id="history", sensor_id="history", received_at=when,
                            payload=decode_export("logs", body(when, event(ident, **attrs)), "application/json"))))


def recover(queue, events):
    with queue.lock, queue.db:
        queue.db.execute("BEGIN IMMEDIATE")
        return usage_recovery.recover(queue.db, queue.usage_scope, "codex", events)


@pytest.mark.parametrize("compact", [False, True])
def test_native_corrects_recovered_request_once_including_compacted_and_cached_totals(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    reader = usage.UsageReader()
    try:
        recovered = history(clock, "request", cost_usd=.5)
        assert recover(queue, [recovered, recovered]) == 1
        assert recover(queue, [recovered]) == 0
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
            assert queue.db.execute("SELECT count(*) FROM usage_compacted").fetchone()[0] == 1
        usage.overview(cfg, 30, reader)
        # A late native report can move a compacted record into the exact recent window.
        queue.usage_scope = "reconnected"
        packet = body(clock.current - timedelta(minutes=1), event("request", input_token_count=2000, cost_usd=.75))
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        result = usage.overview(cfg, 30, reader)
        assert result == read(cfg)
        assert result["summary"]["calls"] == 1 and result["summary"]["tokens"] == 2200
        assert result["summary"]["cost_usd"] == .75
        assert result["periods"]["1"]["summary"]["calls"] == 1
        assert queue.db.execute("SELECT count(*) FROM usage_recovered").fetchone()[0] == 0
        assert queue.db.execute("SELECT count(*) FROM usage_rollups").fetchone()[0] == 0
        assert recover(queue, [recovered]) == 0
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        assert usage.overview(cfg, 30, reader) == result
    finally:
        reader.close()
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_native_first_proves_legacy_keys_without_replacing_reported_values(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        recovered = history(clock, "request", cost_usd=.5)
        queue.confirm(queue.append("logs", body(recovered["time"], event("request", cost_usd=0)), "application/json", 1))
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        with queue.db:
            queue.db.execute("DELETE FROM usage_sources")
        assert not usage_recovery.allowed(queue.db, "codex")
        with queue.db:
            usage_recovery.prove(queue.db, "codex", [recovered["key"]])
        assert usage_recovery.allowed(queue.db, "codex")
        assert recover(queue, [recovered]) == 0
        assert read(cfg)["summary"]["cost_usd"] == 0
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_unknown_native_withdraws_recovery_and_invalidates_checkpoint_generation(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        records = [history(clock, ident, cost_usd=.5) for ident in ("one", "two")]
        assert recover(queue, records) == 2
        # An authoritative request remains when provisional recovery is withdrawn.
        native = body(clock.current - timedelta(days=2), event("known", cost_usd=.75))
        queue.confirm(queue.append("logs", native, "application/json", 1))
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        packet = body(clock.current - timedelta(days=29), event("", cost_usd=.25))
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        report = read(cfg)
        assert report["summary"]["calls"] == 2
        assert report["summary"]["cost_usd"] == 1
        assert report["history_incomplete"]
        assert usage_recovery.generation(queue.db, "codex") == 1
        assert not usage_recovery.allowed(queue.db, "codex")
        assert recover(queue, records) is None
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        assert usage_recovery.generation(queue.db, "codex") == 1
        clock.current += timedelta(days=2)
        with queue.db:
            usage.prune(queue.db)
        assert usage_recovery.allowed(queue.db, "codex")
        assert usage_recovery.generation(queue.db, "codex") == 1
        assert recover(queue, records) == 2
        assert read(cfg)["summary"]["calls"] == 3
    finally:
        queue.close()


@pytest.mark.parametrize("attrs,tokens", [
    ({"input_token_count": "invalid", "output_token_count": "invalid", "model": "", "effort": ""}, 1200),
    ({"input_token_count": 0, "output_token_count": 0}, 0),
])
def test_late_reported_cost_preserves_recovered_tokens_only_when_native_counts_invalid(tmp_path, clock, attrs, tokens):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        recovered = history(clock, "request", cost_usd=.5)
        assert recover(queue, [recovered]) == 1
        queue.confirm(queue.append("logs", body(recovered["time"], event("request", cost_usd=.75, **attrs)), "application/json", 1))
        result = read(cfg)
        assert result["summary"]["tokens"] == tokens
        assert result["summary"]["cost_usd"] == .75
        assert result["by_model"][0]["name"] == "gpt-6.1-sol"
        assert result["by_reasoning_effort"][0]["name"] == "high"
    finally:
        queue.close()


def test_old_writer_price_enrichment_keeps_compacted_recovery_receipt_correct(tmp_path, clock, monkeypatch):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        recovered = history(clock, "request", model="unpriced-model")
        assert recover(queue, [recovered]) == 1
        with queue.db:
            queue.db.execute("UPDATE usage_calls SET cost_usd=.5 WHERE event_key=?", (recovered["key"],))
        monkeypatch.setattr(usage, "MAX_RECORDS", 0)
        with queue.db:
            usage.prune(queue.db)
        assert read(cfg)["summary"]["cost_usd"] == .5
        queue.confirm(queue.append("logs", body(clock.current - timedelta(days=1), event("request", cost_usd=.75)), "application/json", 1))
        assert read(cfg)["summary"]["cost_usd"] == .75
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_later_history_blocks_enrich_recovered_request_without_regressing_it(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        partial = history(clock, "request", output_token_count=1, cost_usd=.1)
        assert recover(queue, [partial]) == 1
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        complete = history(clock, "request", cost_usd=.5)
        assert recover(queue, [complete, partial]) == 0
        assert read(cfg)["summary"]["tokens"] == 1200
        assert read(cfg)["summary"]["cost_usd"] == .5
        assert read(cfg)["summary"]["calls"] == 1
        quoted = history(clock, "request", cost_usd=.75)
        assert recover(queue, [quoted]) == 0
        assert read(cfg)["summary"]["cost_usd"] == .5
        unpriced = history(clock, "missing-price", model="unpriced-model")
        assert recover(queue, [unpriced]) == 1
        with queue.db:
            usage.prune(queue.db)
        priced = history(clock, "missing-price", model="unpriced-model", cost_usd=.25)
        assert recover(queue, [priced]) == 0
        assert read(cfg)["summary"]["priced_calls"] == 2
        assert read(cfg)["summary"]["cost_usd"] == .75
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_legacy_unknown_application_blocks_all_recovery_until_exact_identity_proven(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        known = history(clock, "legacy")
        queue.confirm(queue.append("logs", body(known["time"], event("legacy")), "application/json", 1))
        with queue.db:
            queue.db.execute("DELETE FROM usage_apps")
            queue.db.execute("DELETE FROM usage_sources")
            if compact:
                monkeypatch.setattr(usage, "MAX_RECORDS", 0)
                usage.prune(queue.db)
        assert not usage_recovery.allowed(queue.db, "codex")
        assert not usage_recovery.allowed(queue.db, "claude_code")
        with queue.db:
            usage_recovery.prove(queue.db, "codex", [known["key"]])
        assert usage_recovery.allowed(queue.db, "codex")
        assert usage_recovery.allowed(queue.db, "claude_code")
        queue.confirm(queue.append("logs", body(known["time"], event("")), "application/json", 1))
        assert not usage_recovery.allowed(queue.db, "codex")
        assert usage_recovery.allowed(queue.db, "claude_code")
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_failed_native_correction_rolls_back_recovery_and_export_together(tmp_path, clock, monkeypatch, compact):
    import sqlite3

    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        recovered = history(clock, "request", cost_usd=.5)
        assert recover(queue, [recovered]) == 1
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        before = read(cfg)
        queue.db.execute("""CREATE TEMP TRIGGER fail_correction BEFORE INSERT ON usage_calls
            BEGIN SELECT RAISE(ABORT,'test correction interruption'); END""")
        packet = body(clock.current - timedelta(minutes=1), event("request", cost_usd=.75))
        with pytest.raises(sqlite3.IntegrityError, match="test correction interruption"):
            queue.append("logs", packet, "application/json", 1)
        assert read(cfg) == before
        assert queue.status()["queue_depth"] == 0
        assert queue.db.execute("SELECT count(*) FROM usage_recovered").fetchone()[0] == 1
        queue.db.execute("DROP TRIGGER fail_correction")
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        assert read(cfg)["summary"]["cost_usd"] == .75
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_mixed_batch_preserves_matched_recovery_metadata_before_unknown_withdrawal(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        assert recover(queue, [history(clock, "request", cost_usd=.5)]) == 1
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        packet = body(clock.current - timedelta(minutes=1),
                      event("request", input_token_count="bad", output_token_count="bad", model="", effort="", cost_usd=.75),
                      event("", input_token_count=100, output_token_count=20, cost_usd=.25))
        queue.confirm(queue.append("logs", packet, "application/json", 2))
        result = read(cfg)
        assert result["summary"]["calls"] == 2
        assert result["summary"]["tokens"] == 1320
        assert result["summary"]["cost_usd"] == 1
        assert [row["name"] for row in result["by_model"]] == ["gpt-6.1-sol"]
        assert [row["name"] for row in result["by_reasoning_effort"]] == ["high"]
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
def test_expired_unknown_native_does_not_withdraw_retained_recovery(tmp_path, clock, monkeypatch, compact):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        assert recover(queue, [history(clock, "request", cost_usd=.5)]) == 1
        if compact:
            monkeypatch.setattr(usage, "MAX_RECORDS", 0)
            with queue.db:
                usage.prune(queue.db)
        before = read(cfg)
        queue.confirm(queue.append("logs", body(clock.current - timedelta(days=35), event("")), "application/json", 1))
        assert read(cfg) == before
        assert usage_recovery.allowed(queue.db, "codex")
        assert usage_recovery.generation(queue.db, "codex") == 0
    finally:
        queue.close()


@pytest.mark.parametrize("application,ids,canonical", [
    ("codex", {"response_id": "call"}, True),
    ("codex", {"gen_ai.response.id": "call"}, True),
    ("codex", {"request_id": "http", "response_id": "call"}, False),
    ("codex", {"response_id": "call", "gen_ai.response.id": "different"}, False),
    ("codex", {"request_id": "call"}, False),
    ("claude_code", {"response_id": "call"}, False),
    ("claude_code", {"request_id": "call"}, True),
])
def test_native_identity_must_match_the_provider_transcript_contract(tmp_path, clock, application, ids, canonical):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        when = clock.current - timedelta(minutes=1)
        attrs = dict(input_tokens=100, output_tokens=20, cost_usd=.1, model="a-model", **ids)
        packet = encode_export("logs", cost_payload(application, when, [(application + ".api_request", attrs)]), "application/json")
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        assert usage_recovery.allowed(queue.db, application) is canonical
        if not canonical:
            # A later exact transcript-key match can prove the old identity without changing totals.
            key = next(extract(dict(id="native", sensor_id="original", received_at=when,
                                   payload=decode_export("logs", packet, "application/json"))))["key"]
            with queue.db:
                usage_recovery.prove(queue.db, application, [key])
            assert usage_recovery.allowed(queue.db, application)
        assert read(cfg)["summary"]["calls"] == 1
    finally:
        queue.close()


@pytest.mark.parametrize("proof", ["transcript", "recovered", "batch"])
def test_proven_request_identity_survives_native_replay_without_withdrawing_other_recovery(tmp_path, clock, proof):
    cfg = config(tmp_path)
    queue = ExportQueue(Path(cfg["data_dir"]) / "telemetry.sqlite3", usage_scope="original")
    try:
        when = clock.current - timedelta(minutes=1)
        packet = body(when, event("", request_id="request"))
        matching = history(clock, "request", when=when)
        if proof == "transcript":
            queue.confirm(queue.append("logs", packet, "application/json", 1))
            assert not usage_recovery.allowed(queue.db, "codex")
            with queue.db:
                usage_recovery.prove(queue.db, "codex", [matching["key"]])
        elif proof == "recovered":
            assert recover(queue, [matching]) == 1
        else:
            packet = body(when, event("request"), event("", request_id="request"))
        assert usage_recovery.allowed(queue.db, "codex")
        assert recover(queue, [history(clock, "missing")]) == 1
        queue.confirm(queue.append("logs", packet, "application/json", 1))
        result = read(cfg)["summary"]
        assert result["calls"] == 2 and result["tokens"] == 2400
        assert result["cost_usd"] == pytest.approx(2 * float(matching["usage"]["cost"]))
        assert usage_recovery.generation(queue.db, "codex") == 0
    finally:
        queue.close()


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("age", [2, 35])
def test_upgrade_reconciles_ambiguous_native_writes_from_downgraded_sensor(tmp_path, clock, monkeypatch, compact, age):
    cfg = config(tmp_path)
    path = Path(cfg["data_dir"]) / "telemetry.sqlite3"
    queue = ExportQueue(path, usage_scope="original")
    try:
        assert recover(queue, [history(clock, "request", cost_usd=.5)]) == 1
        old_native = history(clock, "", when=clock.current - timedelta(days=age), cost_usd=.75)
        with queue.db:
            # Older writers have no provenance hook; their delivered export is gone.
            usage.record_calls(queue.db, "old-writer", [old_native])
            if compact:
                monkeypatch.setattr(usage, "MAX_RECORDS", 0)
                usage.prune(queue.db)
        assert queue.status()["queue_depth"] == 0
    finally:
        queue.close()
    queue = ExportQueue(path, usage_scope="original")
    try:
        result = read(cfg)["summary"]
        assert result["calls"] == 1
        assert result["cost_usd"] == (.75 if age == 2 else .5)
        assert usage_recovery.generation(queue.db, "codex") == (1 if age == 2 else 0)
        assert usage_recovery.allowed(queue.db, "codex") is (age == 35)
    finally:
        queue.close()
