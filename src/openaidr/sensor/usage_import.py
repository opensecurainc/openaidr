"""Local usage history, imported once per configured source and pricing revision."""

from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
from itertools import groupby
import json
import os
from pathlib import Path
import re
import sqlite3
from stat import S_ISREG

from pydantic_core import SchemaValidator, core_schema

from openaidr.core.agent_usage import text, token, usage as measure
from openaidr.core.hook_estimates import price
from openaidr.core.reasoning import reasoning_effort
from . import hooks, usage


LINE_LIMIT = 8 << 20
DOCUMENT_LIMIT = 32 << 20
BATCH_SIZE = 1000
# Advance when import parsing or prices change so retained history is revisited.
IMPORT_VERSION = 1


def fields(names, **nested):
    return core_schema.typed_dict_schema({
        **{name: core_schema.typed_dict_field(core_schema.any_schema(), required=False) for name in names},
        **{name: core_schema.typed_dict_field(schema, required=False) for name, schema in nested.items()},
    }, extra_behavior="ignore")


# The existing Pydantic JSON parser skips unselected values in native code.
# Keep values untyped so the accounting rules still decide which counts are valid.
EFFORT_FIELDS = ("reasoning_effort", "gen_ai.request.reasoning_effort", "reasoning.effort",
                 "effort", "model_reasoning_effort")
GEMINI_RECORD = fields(("type", "timestamp", "id", "model", "tokens"))
READERS = {
    "codex": SchemaValidator(fields(("type", "timestamp"), payload=fields(
        ("type", "id", "timestamp", "forked_from_id", "model", "service_tier", "turn_id", "info",
         "response_id", "thread_id", "usage", "thread_token_usage", *EFFORT_FIELDS)))),
    "claude_code": SchemaValidator(fields(("type", "timestamp", "requestId", *EFFORT_FIELDS),
        message=fields(("id", "model", "usage")))),
    "gemini": SchemaValidator(GEMINI_RECORD),
    "workbuddy": SchemaValidator(fields(("type", "role", "timestamp"), providerData=fields(
        ("messageId", "model", "requestModelId"),
        usage=fields(("inputTokens", "outputTokens", "totalTokens")), rawUsage=fields(
            ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens",
             "cache_read_input_tokens", "cache_creation_input_tokens", "prompt_cache_hit_tokens",
             "prompt_cache_write_tokens", "prompt_cache_miss_tokens", "inputTokens"),
            prompt_tokens_details=fields(("cached_tokens",)),
            input_tokens_details=fields(("cached_tokens",)),
            inputTokensDetails=core_schema.union_schema([
                fields(("cached_tokens",)), core_schema.list_schema(fields(("cached_tokens",))),
            ]))))),
}
GEMINI_DOCUMENT = SchemaValidator(fields((), messages=core_schema.list_schema(
    core_schema.union_schema([GEMINI_RECORD, core_schema.any_schema()], mode="left_to_right"))))
# Standard text input, cached input, output USD per million tokens.
# https://ai.google.dev/gemini-api/docs/pricing (2026-10-28).
GEMINI_RATES = {
    "gemini-2.5-pro": ("1.25", "0.125", "10"),
    "gemini-2.5-flash": ("0.3", "0.03", "2.5"),
    "gemini-2.5-flash-lite": ("0.1", "0.01", "0.4"),
    "gemini-3-flash-preview": ("0.5", "0.05", "3"),
    "gemini-3.1-pro-preview": ("2", "0.2", "12"),
    "gemini-3.1-pro-preview-customtools": ("2", "0.2", "12"),
    "gemini-3.1-flash-lite": ("0.25", "0.025", "1.5"),
    "gemini-3.5-flash-lite": ("0.3", "0.03", "2.5"),
    "gemini-4-argon": ("2", "0.1", "10"),
}


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except (AttributeError, ValueError, TypeError):
        return None


def event(application, ident, when, attrs, effort):
    measured = measure(attrs, application + ".api_request", when=when)
    if measured is None or not measured["tokens"]:
        return None
    key = hashlib.sha256(json.dumps([application, ident], sort_keys=True).encode()).hexdigest()
    return dict(key="history:" + key, time=when, name=application + ".api_request",
                model=text(attrs, "model") or "Unattributed", reasoning_effort=effort or "unknown",
                usage=measured)


def claude(record):
    message = record.get("message")
    if record.get("type") != "assistant" or not isinstance(message, dict):
        return None
    counts = message.get("usage")
    when = timestamp(record.get("timestamp"))
    ident = text(message, "id") or text(record, "requestId")
    if not isinstance(counts, dict) or not when or not ident:
        return None
    attrs = dict(model=text(message, "model"), input_tokens=counts.get("input_tokens"),
                 output_tokens=counts.get("output_tokens"),
                 cache_read_tokens=counts.get("cache_read_input_tokens", 0),
                 cache_creation_tokens=counts.get("cache_creation_input_tokens", 0))
    result = event("claude_code", ident, when, attrs, reasoning_effort(record))
    if result is not None:
        result["usage"]["cost"] = claude_cost(attrs, counts)
    return result


def claude_cost(attrs, counts):
    """Apply the bundled base prices and recorded cache durations/modifiers."""
    model = re.sub(r"-\d{8}$", "", attrs["model"].lower().replace(".", "-"))
    incoming, outgoing, cached, written = (
        token(attrs, key) for key in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")
    )
    if None in (incoming, outgoing, cached, written):
        return None
    cache = counts.get("cache_creation") or {}
    if not isinstance(cache, dict):
        return None
    hour = token(cache, "ephemeral_1h_input_tokens", optional=True)
    short = token(cache, "ephemeral_5m_input_tokens", optional=True)
    if hour is None or short is None or hour + short > written:
        return None
    # https://platform.claude.com/docs/en/about-claude/pricing (2026-11-02).
    hit_rate = Decimal({"claude-fable-5-1": "0.025", "claude-opus-5-5": "0.05",
                        "claude-sonnet-5-5": "0.05"}.get(model, "0.1"))
    cost = price(model, incoming + cached * hit_rate + (written - hour) * Decimal("1.25") + hour * 2, outgoing)
    if cost is None or counts.get("service_tier") not in (None, "standard"):
        return None
    speed = counts.get("speed", "standard")
    if speed == "fast" and model in {"claude-opus-5-5", "claude-opus-5", "claude-opus-4-8"}:
        cost *= 2
    elif speed != "standard":
        return None
    geo = counts.get("inference_geo", "global")
    if geo == "us":
        cost *= Decimal("1.1")
    elif geo != "global":
        return None
    return cost


def codex_counts(value):
    if not isinstance(value, dict):
        return None
    counts = {target: token(value, source, optional=optional) for target, source, optional in (
        ("input_tokens", "input_tokens", False), ("output_tokens", "output_tokens", False),
        ("cached_token_count", "cached_input_tokens", True), ("cache_write_token_count", "cache_write_input_tokens", True),
    )}
    return counts if all(count is not None for count in counts.values()) else None


def codex(record, state):
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("type") == "session_meta":
        state["session"] = text(payload, "id")
        state["forked_at"] = timestamp(payload.get("timestamp")) if payload.get("forked_from_id") else None
        return None
    if record.get("type") == "turn_context":
        state["model"] = text(payload, "model")
        state["effort"] = reasoning_effort(payload)
        state["tier"] = text(payload, "service_tier")
        state["turn"] = text(payload, "turn_id")
        return None
    if record.get("type") != "event_msg" or payload.get("type") != "token_count":
        return None
    info = payload.get("info")
    when = timestamp(record.get("timestamp"))
    if not isinstance(info, dict) or not when:
        return None
    total = codex_counts(info.get("total_token_usage"))
    if total is None:
        return None
    previous, state["previous"] = state.get("previous"), total
    if previous is not None:
        counts = {key: value - previous[key] for key, value in total.items()}
        if any(value < 0 for value in counts.values()):
            return None
    else:
        counts = codex_counts(info.get("last_token_usage")) or total
        if any(counts[key] > value for key, value in total.items()):
            return None
    # Copied parent history in a fork is already accounted for by its source.
    if state.get("forked_at") and when < state["forked_at"]:
        return None
    ident = state.get("turn") or state.get("session")
    if not ident:
        return None
    attrs = dict(counts, model=state.get("model", ""), service_tier=state.get("tier", ""))
    return event("codex", [ident, record["timestamp"], total], when, attrs, state.get("effort"))


def gemini(record):
    counts = record.get("tokens")
    when = timestamp(record.get("timestamp"))
    ident = text(record, "id")
    if record.get("type") != "gemini" or not isinstance(counts, dict) or not when or not ident:
        return None
    incoming, outgoing, cached, thoughts = (
        token(counts, key, optional=key in {"cached", "thoughts"}) for key in ("input", "output", "cached", "thoughts")
    )
    if None in (incoming, outgoing, cached, thoughts) or cached > incoming:
        return None
    model = text(record, "model")
    result = event("gemini", ident, when, dict(model=model, input_tokens=incoming - cached,
                   cache_read_tokens=cached, output_tokens=outgoing + thoughts), None)
    rates = GEMINI_RATES.get(model)
    if result is not None and rates is not None:
        rates = list(map(Decimal, rates))
        if model in {"gemini-2.5-pro", "gemini-3.1-pro-preview", "gemini-3.1-pro-preview-customtools"} and incoming > 200_000:
            rates = [rates[0] * 2, rates[1] * 2, rates[2] * Decimal("1.5")]
        if model == "gemini-4-argon" and when >= datetime(2026, 12, 1, tzinfo=timezone.utc):
            rates = [rate * 2 for rate in rates]
        result["usage"]["cost"] = sum(n * r for n, r in zip((incoming - cached, cached, outgoing + thoughts), rates)) / 1_000_000
    return result


def records(path, stop, paused, application=None):
    with path.open("rb") as source:
        if path.suffix == ".json":
            raw = source.read(DOCUMENT_LIMIT + 1)
            if len(raw) > DOCUMENT_LIMIT:
                return
            try:
                doc = decode(raw, GEMINI_DOCUMENT if application == "gemini" else None)
            except (ValueError, UnicodeError, RecursionError):
                return
            messages = doc.get("messages") if isinstance(doc, dict) else None
            if isinstance(messages, list):
                for record in messages:
                    if stop.is_set() or paused():
                        raise InterruptedError
                    if isinstance(record, dict):
                        yield record
            return
        while line := source.readline(LINE_LIMIT + 1):
            if stop.is_set() or paused():
                raise InterruptedError
            if len(line) > LINE_LIMIT:
                while line and not line.endswith(b"\n"):
                    if stop.is_set() or paused():
                        raise InterruptedError
                    line = source.readline(LINE_LIMIT + 1)
                continue
            try:
                record = decode(line, READERS.get(application))
            except (ValueError, UnicodeError, RecursionError):
                continue
            if isinstance(record, dict):
                yield record


def decode(raw, reader):
    if reader is not None:
        try:
            return reader.validate_json(raw)
        except ValueError:
            # Preserve the original handling of unusual encodings or malformed
            # optional fields that are irrelevant to this particular event.
            pass
    return json.loads(raw)


def roots(config, application):
    from .integrations import configured_paths

    if application == "workbuddy":
        from .workbuddy import config_roots

        return [(home / "projects").absolute() for home in config_roots()]
    agent = "codex" if application == "codex" else "claude"
    if application == "gemini":
        home = Path(os.environ.get("GEMINI_CLI_HOME") or Path.home()) / ".gemini"
        return [home / "tmp"]
    homes = {hooks.settings_path(agent, config).parent,
             *(path.parent for path in configured_paths(config, agent))}
    if agent == "codex":
        # Shared config symlinks do not imply shared session directories.
        homes.update(path.parent for path in hooks.codex_paths(config))
    names = ("sessions", "archived_sessions") if agent == "codex" else ("projects",)
    return sorted({(home / name).expanduser().resolve() for home in homes for name in names})


def files(config, application, since):
    found = {}

    def failed(error):
        raise error

    for root in roots(config, application):
        if not root.exists():
            continue
        for directory, _, names_in_directory in os.walk(root, onerror=failed):
            if application == "gemini" and "chats" not in Path(directory).relative_to(root).parts:
                continue
            for name in names_in_directory:
                if name.endswith((".json", ".jsonl") if application == "gemini" else ".jsonl"):
                    path = (Path(directory) / name).resolve()
                    try:
                        modified = path.stat().st_mtime
                    except FileNotFoundError:
                        continue
                    if modified >= since:
                        found[path] = modified
    return sorted(found, key=found.get, reverse=True)


def store(queue, application, events):
    if not events:
        return
    with queue.lock, queue.db:
        cutoff = queue.db.execute("SELECT cutoff FROM usage_imports WHERE scope=? AND application=?",
                                  (queue.usage_scope, application)).fetchone()[0]
        selected = {}
        for item in events:
            if item["time"].timestamp() >= cutoff:
                continue
            previous = selected.get(item["key"])
            if previous is None or previous["usage"]["tokens"] < item["usage"]["tokens"]:
                selected[item["key"]] = item
            elif previous["usage"]["tokens"] == item["usage"]["tokens"] and previous["usage"]["cost"] is None:
                if metadata(previous)[:-1] == metadata(item)[:-1]:
                    selected[item["key"]] = item
        events = list(selected.values())
        previous = {}
        for start in range(0, len(events), 400):
            keys = [item["key"] for item in events[start:start + 400]]
            previous.update(queue.db.execute(
                f"SELECT event_key,tokens FROM usage_calls WHERE scope=? AND event_key IN ({','.join('?' for _ in keys)})",
                (queue.usage_scope, *keys)))
        # Agents can write several blocks with the same message ID. Keep
        # final usage, including when a scan is interrupted and restarted.
        queue.db.executemany("DELETE FROM usage_calls WHERE scope=? AND event_key=?",
            [(queue.usage_scope, item["key"]) for item in events
             if item["key"] in previous and previous[item["key"]] < item["usage"]["tokens"]])
        usage.record_calls(queue.db, queue.usage_scope, events)
        usage.prune(queue.db, compact=False)


def metadata(item):
    counts = item["usage"]
    return (item["key"], item["name"].split(".")[0], item["time"].timestamp(), item["model"],
            item["reasoning_effort"], counts["tokens"], counts["cache_read_tokens"],
            counts["input_tokens"] + counts["cache_write_tokens"], counts["output_tokens"],
            float(counts["cost"]) if counts["cost"] is not None else None)


def staged_events(rows):
    for key, application, when, model, effort, tokens, cached, incoming, outgoing, cost in rows:
        yield dict(key=key, name=application + ".api_request", time=datetime.fromtimestamp(when, timezone.utc),
                   model=model, reasoning_effort=effort, usage=dict(tokens=tokens, cache_read_tokens=cached,
                   input_tokens=incoming, cache_write_tokens=0, output_tokens=outgoing, cost=cost))


def stage(db, events):
    db.executemany("""INSERT INTO history VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(event_key) DO UPDATE SET
            application=excluded.application,happened_at=excluded.happened_at,
            model=excluded.model,effort=excluded.effort,tokens=excluded.tokens,
            cached=excluded.cached,incoming=excluded.incoming,outgoing=excluded.outgoing,cost=excluded.cost
        WHERE excluded.tokens>tokens OR (cost IS NULL AND excluded.cost IS NOT NULL
            AND happened_at=excluded.happened_at AND model=excluded.model AND effort=excluded.effort
            AND tokens=excluded.tokens AND cached=excluded.cached
            AND incoming=excluded.incoming AND outgoing=excluded.outgoing)""", map(metadata, events))


def history_once(config, queue, stop, paused=lambda: False):
    if not (config.get("telemetry") or {}).get("enabled", True) or stop.is_set() or paused():
        return False
    fingerprints = {application: hashlib.sha256(json.dumps(
        [IMPORT_VERSION, *map(str, roots(config, application))]).encode()).hexdigest()
        for application in ("codex", "claude_code", "gemini")}
    with queue.lock, queue.db:
        first = queue.db.execute("SELECT scope,started_at FROM usage_history ORDER BY rowid LIMIT 1").fetchone()
        if not first:
            return True
        for application in ("codex", "claude_code", "gemini"):
            previous = queue.db.execute("""SELECT i.completed,s.fingerprint FROM usage_imports i
                LEFT JOIN usage_import_sources s USING(scope,application)
                WHERE i.scope=? AND i.application=?""", (queue.usage_scope, application)).fetchone()
            if previous is not None and previous[0] == 1 and previous[1] == fingerprints[application]:
                continue
            # Older sensors treat every pending (0) non-Codex import as Claude.
            # State 2 keeps unfinished Gemini imports invisible on downgrade.
            if previous is None:
                earliest = queue.db.execute("""SELECT min(u.happened_at) FROM usage_calls u JOIN usage_apps a
                    USING(scope,event_key) WHERE a.application=? AND u.event_key NOT LIKE 'history:%'""",
                    (application,)).fetchone()[0]
                # Gemini starts its import when support is installed, including upgrades.
                start = usage.datetime.now(timezone.utc).timestamp() if application == "gemini" else first["started_at"]
                cutoff = min(start, earliest) if earliest is not None else start
                queue.db.execute("INSERT INTO usage_imports VALUES (?,?,?,?)",
                                 (queue.usage_scope, application, cutoff, 2 if application == "gemini" else 0))
            elif previous[1] != fingerprints[application]:
                queue.db.execute("UPDATE usage_imports SET completed=? WHERE scope=? AND application=?",
                                 (2 if application == "gemini" else 0, queue.usage_scope, application))
        pending = queue.db.execute("""SELECT application,cutoff FROM usage_imports WHERE scope=?
            AND completed IN (0,2) AND application IN ('codex','claude_code','gemini')""",
                                   (queue.usage_scope,)).fetchall()
    if not pending:
        return True
    now = usage.datetime.now(timezone.utc)
    since = usage.local_start(now, 30).timestamp()
    recent = now.timestamp() - 86400
    completed = []
    # A private temporary database bounds memory and retains only accounting
    # fields. It is deleted on close, including cancellation and failed scans.
    with closing(sqlite3.connect("")) as history:
        history.execute("""CREATE TABLE history (
            event_key TEXT PRIMARY KEY, application TEXT, happened_at REAL,
            model TEXT, effort TEXT, tokens INTEGER, cached INTEGER,
            incoming INTEGER, outgoing INTEGER, cost REAL)""")

        def flush(application, batch):
            stage(history, batch)
            current = []
            for key in dict.fromkeys(item["key"] for item in batch if item["time"].timestamp() >= recent):
                row = history.execute("SELECT * FROM history WHERE event_key=? AND happened_at>=?",
                                      (key, recent)).fetchone()
                if row:
                    current.append(row)
            store(queue, application, list(staged_events(current)))
            batch.clear()

        for application, cutoff in pending:
            batch = []
            complete = True
            try:
                paths = files(config, application, since)
            except OSError:
                continue
            for path in paths:
                state = {}
                try:
                    # Codex cumulative counters and fork metadata need source
                    # order. Defer old writes instead of reversing that input.
                    for record in records(path, stop, paused, application):
                        item = codex(record, state) if application == "codex" else gemini(record) if application == "gemini" else claude(record)
                        if item and since <= item["time"].timestamp() < cutoff:
                            batch.append(item)
                        if len(batch) >= BATCH_SIZE:
                            flush(application, batch)
                except FileNotFoundError:
                    continue
                except InterruptedError:
                    return False
                except OSError:
                    complete = False
            if stop.is_set() or paused():
                return False
            flush(application, batch)
            if complete:
                completed.append(application)

        cursor = history.execute("SELECT * FROM history ORDER BY happened_at DESC,event_key")
        while rows := cursor.fetchmany(BATCH_SIZE):
            if stop.is_set() or paused():
                return False
            for _, day_rows in groupby(rows, key=lambda row: datetime.fromtimestamp(row[2]).date()):
                batches = {}
                for item in staged_events(day_rows):
                    batches.setdefault(item["name"].split(".")[0], []).append(item)
                for application, batch in batches.items():
                    store(queue, application, batch)
        with queue.lock, queue.db:
            queue.db.executemany("UPDATE usage_imports SET completed=1 WHERE scope=? AND application=?",
                                 [(queue.usage_scope, application) for application in completed])
            queue.db.executemany("INSERT INTO usage_import_sources VALUES (?,?,?) "
                                 "ON CONFLICT(scope,application) DO UPDATE SET fingerprint=excluded.fingerprint",
                                 [(queue.usage_scope, application, fingerprints[application]) for application in completed])
            usage.prune(queue.db)
    return len(completed) == len(pending)


def request_record(record, application, state, cutoff, sensor_id=""):
    """Return an exact request key and accounting fields, never match by time/counts."""
    if application == "workbuddy":
        from .workbuddy_usage import request_record as workbuddy_record

        return workbuddy_record(record, sensor_id)
    when = timestamp(record.get("timestamp"))
    if application == "claude_code":
        if record.get("type") != "assistant":
            return None, None, 0, 0
        ident = text(record, "requestId")
        item = claude(record)
        counts = (record.get("message") or {}).get("usage")
        if isinstance(counts, dict) and all(token(counts, key, optional=True) == 0 for key in (
                "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")):
            return None, None, 0, 0
        relevant = item is not None and when.timestamp() >= cutoff
        if not ident:
            return None, None, 0, int(relevant)
    else:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return None, None, 0, 0
        kind = record.get("type")
        if kind == "turn_context":
            state.update(turn=text(payload, "turn_id"), model=text(payload, "model"),
                         effort=reasoning_effort(payload), tier=text(payload, "service_tier"))
            return None, None, 0, 0
        if kind != "token_usage_record":
            return None, None, 0, 0
        ident = text(payload, "response_id")
        counts = codex_counts(payload.get("usage"))
        if counts is not None and not any(counts.values()):
            return None, None, 0, 0
        if not ident:
            return None, None, 0, int(bool(counts and when and when.timestamp() >= cutoff))
        item = None
        if counts is not None and when:
            same_turn = text(payload, "turn_id") == state.get("turn") and bool(state.get("turn"))
            item = event(application, ident, when, dict(counts, model=state.get("model", "") if same_turn else "",
                         service_tier=state.get("tier", "") if same_turn else ""),
                         state.get("effort") if same_turn else None)
    # This is the existing core.agent_usage.extract identity for both providers.
    key = hashlib.sha256(json.dumps((application, ident)).encode()).hexdigest()
    if item is not None:
        item["key"] = key
        item["attributes"] = {"service_tier": state.get("tier", "") if application == "codex"
                              else text((record.get("message") or {}).get("usage") or {}, "service_tier")}
    return key, item, int(item is None), 0


def recovery_status(db):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "usage_request_sources" not in tables:
        return None
    source = db.execute("SELECT min(scanned_at),coalesce(sum(inaccessible),0) FROM usage_request_sources").fetchone()
    counts = db.execute("""SELECT coalesce(sum(blocked),0),coalesce(sum(inaccessible),0),
        coalesce(sum(invalid),0),coalesce(sum(unsupported),0),coalesce(sum(offset<size),0)
        FROM usage_request_files""").fetchone()
    partial = db.execute("SELECT count(*) FROM usage_request_aliases WHERE partial=1").fetchone()[0] if "usage_request_aliases" in tables else 0
    return dict(last_scan_at=datetime.fromtimestamp(source[0], timezone.utc).isoformat() if source[0] else None,
                blocked_files=counts[0], inaccessible_sources=source[1],
                inaccessible_files=counts[1], invalid_records=counts[2], unsupported_records=counts[3],
                pending_files=counts[4], unreconciled_records=partial)


def request_link(record, application, state, item, cutoff):
    """Link source-local counters; preserve uncertain legacy overlap as partial."""
    if application == "workbuddy":
        return [], None, 0  # WorkBuddy never used the legacy history importer.
    if application == "claude_code":
        legacy = claude(record)
        if item and legacy and legacy["time"].timestamp() < cutoff:
            return [(item, legacy["key"], False)], None, 0
        return [], None, 0
    legacy_state = state.setdefault("legacy", {})
    if isinstance(legacy_state.get("forked_at"), str):
        legacy_state["forked_at"] = timestamp(legacy_state["forked_at"])
    legacy = codex(record, legacy_state)
    payload = record.get("payload") or {}
    pending = state.setdefault("pending", [])
    if record.get("type") == "token_usage_record" and item:
        pending.append(dict(event=metadata(item), turn=text(payload, "turn_id"),
                            total=codex_counts(payload.get("thread_token_usage")),
                            counts=codex_counts(payload.get("usage")),
                            tier=text(item.get("attributes", {}), "service_tier")))
    elif legacy is None:
        return [], None, 0
    if legacy:
        measured = legacy["usage"]
        counts = dict(input_tokens=measured["input_tokens"] + measured["cache_write_tokens"] + measured["cache_read_tokens"],
                      output_tokens=measured["output_tokens"], cached_token_count=measured["cache_read_tokens"],
                      cache_write_token_count=measured["cache_write_tokens"])
        state["link_legacy"] = dict(key=legacy["key"], time=legacy["time"].timestamp(), counts=counts,
            total=codex_counts((payload.get("info") or {}).get("total_token_usage")), turn=legacy_state.get("turn"),
            unmatched=int(not pending and legacy["time"].timestamp() >= cutoff))
    linked = state.get("link_legacy")
    if not pending:
        return [], None, linked["unmatched"] if legacy else 0
    if not linked or (legacy is None and pending[-1]["total"] != linked["total"]):
        return [], None, 0
    state.pop("link_legacy", None)
    state["pending"] = []
    requests = []
    for entry in pending:
        request = next(staged_events([entry["event"]]))
        request["attributes"] = {"service_tier": entry["tier"]}
        requests.append(request)
    exact = (len(pending) == 1 and pending[0]["turn"] == linked["turn"] and linked["total"]
             and pending[0]["total"] == linked["total"] and pending[0]["counts"] == linked["counts"])
    if linked["time"] < cutoff:
        return [(request, linked["key"], not exact) for request in requests], None, 0
    if exact:
        request = requests[0]
        return [], request if request["time"].timestamp() < cutoff else None, -linked["unmatched"]
    return [], None, int(not linked["unmatched"])


def requests_once(config, queue, stop, paused=lambda: False):
    from . import usage_recovery, usage_recovery_aliases

    if not (config.get("telemetry") or {}).get("enabled", True) or stop.is_set() or paused():
        return False
    now = usage.datetime.now(timezone.utc).timestamp()
    since = usage.local_start(usage.datetime.now(timezone.utc), 30).timestamp()
    with queue.lock, queue.db:
        queue.db.executescript("""
            CREATE TABLE IF NOT EXISTS usage_request_files (
                application TEXT NOT NULL, path TEXT NOT NULL, device INTEGER NOT NULL,
                inode INTEGER NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                offset INTEGER NOT NULL, anchor TEXT NOT NULL, state TEXT NOT NULL,
                generation INTEGER NOT NULL, version INTEGER NOT NULL, blocked INTEGER NOT NULL, invalid INTEGER NOT NULL,
                unsupported INTEGER NOT NULL, inaccessible INTEGER NOT NULL, scanned_at REAL NOT NULL,
                PRIMARY KEY(application,path)
            );
            CREATE TABLE IF NOT EXISTS usage_request_sources (
                application TEXT PRIMARY KEY, scanned_at REAL NOT NULL, inaccessible INTEGER NOT NULL
            );
        """)
        usage_recovery_aliases.initialize(queue.db)
        cutoffs = dict(queue.db.execute("SELECT application,min(cutoff) FROM usage_imports GROUP BY application"))
        unfinished = {row[0] for row in queue.db.execute(
            "SELECT application FROM usage_imports WHERE scope=? AND completed IN (0,2)", (queue.usage_scope,))}
        saved = {(row["application"], row["path"]): dict(row) for row in queue.db.execute("SELECT * FROM usage_request_files")}
        cutoffs["workbuddy"] = since
        generations = {app: usage_recovery.generation(queue.db, app) for app in ("codex", "claude_code", "workbuddy")}
        allowed = {app: usage_recovery.allowed(queue.db, app) for app in generations}
    plans, sources, current_roots = {}, {}, {}
    with closing(sqlite3.connect("")) as staged:
        staged.execute("""CREATE TABLE history (event_key TEXT PRIMARY KEY, application TEXT,
            happened_at REAL,model TEXT,effort TEXT,tokens INTEGER,cached INTEGER,incoming INTEGER,
            outgoing INTEGER,cost REAL)""")
        staged.execute("CREATE TABLE proof (application TEXT,event_key TEXT,PRIMARY KEY(application,event_key))")
        staged.execute("CREATE TABLE tiers (event_key TEXT PRIMARY KEY,service_tier TEXT)")
        staged.execute("CREATE TABLE aliases (application TEXT,event_key TEXT,legacy_key TEXT,accounting TEXT,tier TEXT,partial INTEGER,PRIMARY KEY(event_key,legacy_key))")

        def bind_aliases():
            cursor = staged.execute("SELECT application,legacy_key,accounting,tier,partial FROM aliases")
            while rows := cursor.fetchmany(BATCH_SIZE):
                with queue.lock, queue.db:
                    queue.db.execute("BEGIN IMMEDIATE")
                    linked = {}
                    for app, legacy_key, accounting, tier, partial in rows:
                        item = next(staged_events([json.loads(accounting)]))
                        item["attributes"] = {"service_tier": tier}
                        if usage_recovery_aliases.bind(queue.db, queue.usage_scope, app, item, legacy_key, partial=partial):
                            linked.setdefault(app, []).append(item)
                    for app, events in linked.items():
                        usage_recovery.recover(queue.db, queue.usage_scope, app, events)
            staged.execute("DELETE FROM aliases")

        def save(batch):
            stage(staged, batch)
            staged.executemany("INSERT OR REPLACE INTO tiers VALUES (?,?)", [
                (item["key"], text(item.get("attributes", {}), "service_tier")) for item in batch])

        def scan(path, app, previous, stat=None, reset=False):
            if app == "workbuddy":
                from .privacy import PrivacyGuard

                checked = PrivacyGuard().check(path)
                if not any(checked.is_relative_to(root) for root in current_roots[app]):
                    raise PermissionError
                path = checked
            if stat is None:
                stat = path.stat()
            if app == "workbuddy" and not S_ISREG(stat.st_mode):
                raise OSError("WorkBuddy history source is not a regular file")
            start = 0 if reset else previous.get("offset", 0)
            state = {} if not start else json.loads(previous["state"])
            invalid = 0 if not start else previous["invalid"]
            unsupported = 0 if not start else previous["unsupported"]
            batch, proof = [], []
            with path.open("rb") as source:
                if start:
                    source.seek(max(0, start - 4096))
                    if hashlib.sha256(source.read(min(start, 4096))).hexdigest() != previous["anchor"]:
                        return scan(path, app, previous, stat, reset=True)
                source.seek(start)
                offset = start
                while source.tell() < stat.st_size:
                    if stop.is_set() or paused():
                        raise InterruptedError
                    line_start = source.tell()
                    raw = source.readline(min(LINE_LIMIT + 1, stat.st_size - line_start))
                    oversized = len(raw) > LINE_LIMIT
                    while oversized and raw and not raw.endswith(b"\n") and source.tell() < stat.st_size:
                        raw = source.readline(min(LINE_LIMIT + 1, stat.st_size - source.tell()))
                    if not raw.endswith(b"\n"):
                        break
                    offset = source.tell()
                    if oversized:
                        invalid += 1
                        continue
                    try:
                        # Never materialize unselected WorkBuddy prompt/tool fields,
                        # including on malformed records that the schema rejects.
                        record = READERS[app].validate_json(raw) if app == "workbuddy" else decode(raw, READERS[app])
                        if not isinstance(record, dict):
                            raise ValueError("not a record")
                        key, item, bad, unmatched = request_record(record, app, state, cutoffs[app], queue.usage_scope)
                        aliases, boundary, unlinked = request_link(record, app, state, item, cutoffs[app])
                    except (ValueError, UnicodeError, RecursionError, TypeError, AttributeError):
                        invalid += 1
                        continue
                    invalid += bad
                    unsupported += unmatched + unlinked
                    if key:
                        proof.append((app, key))
                    for linked, legacy_key, partial in aliases:
                        staged.execute("INSERT OR REPLACE INTO aliases VALUES (?,?,?,?,?,?)", (app, linked["key"], legacy_key,
                            json.dumps(metadata(linked)), text(linked.get("attributes", {}), "service_tier"), partial))
                    if boundary and boundary["time"].timestamp() >= since:
                        batch.append(boundary)
                    if item and max(since, cutoffs[app]) <= item["time"].timestamp():
                        batch.append(item)
                    if len(proof) >= BATCH_SIZE:
                        staged.executemany("INSERT OR IGNORE INTO proof VALUES (?,?)", proof)
                        proof.clear()
                    if len(batch) >= BATCH_SIZE:
                        save(batch)
                        batch.clear()
                source.seek(max(0, offset - 4096))
                anchor = hashlib.sha256(source.read(min(offset, 4096))).hexdigest()
            save(batch)
            staged.executemany("INSERT OR IGNORE INTO proof VALUES (?,?)", proof)
            if "pending" in state:
                state["pending"] = [entry for entry in state["pending"] if entry["event"][2] >= since]
            return dict(application=app, path=str(path), device=stat.st_dev, inode=stat.st_ino,
                        size=stat.st_size, mtime_ns=stat.st_mtime_ns, offset=offset, anchor=anchor,
                        state=json.dumps(state, default=lambda value: value.isoformat()), generation=generations[app], version=IMPORT_VERSION, blocked=0,
                        invalid=invalid, unsupported=unsupported, inaccessible=0, scanned_at=now)

        try:
            for app in generations:
                if app not in cutoffs:
                    continue
                from .integrations import manifest

                unavailable, seen = set(), set()
                app_roots = roots(config, app)
                current_roots[app] = app_roots
                if app in unfinished:
                    sources[app] = 1
                    continue
                guard = None
                if app == "workbuddy":
                    from .privacy import PrivacyGuard

                    guard = PrivacyGuard()
                    known_homes = set()
                else:
                    agent = "codex" if app == "codex" else "claude"
                    known_homes = {Path(path).expanduser().resolve().parent for path, entry in manifest(config).items()
                                   if entry.get("agent") == agent}
                    explicit = ((config.get("hooks") or {}).get("homes") or {}).get(agent)
                    if explicit:
                        known_homes.add(Path(explicit).expanduser().resolve())
                for index, root in enumerate(app_roots):
                    if guard:
                        try:
                            root = guard.check(root)
                            app_roots[index] = root
                        except OSError:
                            unavailable.add(str(root))
                            continue
                    if not root.exists():
                        if root.parent in known_homes and not root.parent.exists():
                            unavailable.add(str(root.parent))
                        continue
                    if guard:
                        from .workbuddy_usage import history_walk

                        walk = history_walk(root, guard, unavailable, lambda: stop.is_set() or paused())
                    else:
                        walk = os.walk(root, onerror=lambda error: unavailable.add(str(error.filename)))
                    for directory, _, names in walk:
                        for name in names:
                            if not name.endswith(".jsonl"):
                                continue
                            if guard:
                                try:
                                    path = guard.check(Path(directory) / name)
                                    if not path.is_relative_to(root):
                                        raise PermissionError
                                except OSError:
                                    unavailable.add(str(Path(directory) / name))
                                    continue
                            else:
                                path = (Path(directory) / name).resolve()
                            key = (app, str(path))
                            seen.add(key)
                            previous = saved.get(key, {})
                            try:
                                stat = path.stat()
                                if stat.st_mtime < since:
                                    continue
                                same = previous and (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) == (
                                    previous["device"], previous["inode"], previous["size"], previous["mtime_ns"])
                                replay = previous and (previous["blocked"] or previous["generation"] != generations[app])
                                revised = previous and previous["version"] != IMPORT_VERSION
                                newly_blocked = previous and not previous["blocked"] and not allowed[app]
                                if same and not previous["inaccessible"] and not revised and not newly_blocked and not (replay and allowed[app]):
                                    if replay or not allowed[app]:
                                        plans[key] = {**previous, "blocked": 1}
                                    continue
                                reset = bool(previous and (revised or newly_blocked or (replay and allowed[app]) or stat.st_size <= previous["size"]
                                    or (stat.st_dev, stat.st_ino) != (previous["device"], previous["inode"])))
                                plans[key] = scan(path, app, previous, stat, reset)
                            except InterruptedError:
                                raise
                            except OSError:
                                plans[key] = {**(previous or dict(application=app, path=str(path), device=0, inode=0,
                                    size=0, mtime_ns=0, offset=0, anchor="", state="{}", generation=generations[app], version=IMPORT_VERSION,
                                    blocked=0, invalid=0, unsupported=0, scanned_at=now)), "inaccessible": 1}
                for key, previous in saved.items():
                    if key[0] == app and key not in seen and any(Path(key[1]).is_relative_to(root) for root in app_roots):
                        plans[key] = {**previous, "inaccessible": 1}
                sources[app] = len(unavailable)
            # Identity proof precedes admission, including across applications for
            # old compacted rows whose original application was not retained.
            bind_aliases()
            for app in generations:
                cursor = staged.execute("SELECT event_key FROM proof WHERE application=?", (app,))
                while rows := cursor.fetchmany(BATCH_SIZE):
                    with queue.lock, queue.db:
                        queue.db.execute("BEGIN IMMEDIATE")
                        usage_recovery.prove(queue.db, app, [row[0] for row in rows])
            for app in sources:
                with queue.lock:
                    permitted = app not in unfinished and usage_recovery.allowed(queue.db, app)
                if permitted:
                    for key, previous in saved.items():
                        if key[0] != app or not previous["blocked"] or (allowed[app] and key in plans) or not any(
                                Path(key[1]).is_relative_to(root) for root in current_roots[app]):
                            continue
                        path = Path(key[1])
                        try:
                            plans[key] = scan(path, app, previous, reset=True)
                        except InterruptedError:
                            raise
                        except OSError:
                            plans[key] = {**previous, "inaccessible": 1}
                    bind_aliases()
                    cursor = staged.execute("SELECT * FROM history WHERE application=? ORDER BY happened_at,event_key", (app,))
                    while rows := cursor.fetchmany(BATCH_SIZE):
                        if stop.is_set() or paused():
                            return False
                        with queue.lock, queue.db:
                            queue.db.execute("BEGIN IMMEDIATE")
                            events = list(staged_events(rows))
                            for item in events:
                                tier = staged.execute("SELECT service_tier FROM tiers WHERE event_key=?", (item["key"],)).fetchone()
                                item["attributes"] = {"service_tier": tier[0] if tier else ""}
                            result = usage_recovery.recover(queue.db, queue.usage_scope, app, events)
                        if result is None:
                            permitted = False
                            break
                with queue.lock, queue.db:
                    queue.db.execute("BEGIN IMMEDIATE")
                    permitted = permitted and usage_recovery.allowed(queue.db, app)
                    for key, plan in plans.items():
                        if key[0] == app:
                            plan["blocked"] = int(not permitted)
                            queue.db.execute("INSERT OR REPLACE INTO usage_request_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                             tuple(plan[field] for field in ("application", "path", "device", "inode", "size", "mtime_ns",
                                                 "offset", "anchor", "state", "generation", "version", "blocked", "invalid", "unsupported", "inaccessible", "scanned_at")))
                    queue.db.execute("INSERT OR REPLACE INTO usage_request_sources VALUES (?,?,?)", (app, now, sources[app]))
                    queue.db.executemany("DELETE FROM usage_request_files WHERE application=? AND path=?", [
                        key for key in saved if key[0] == app and not any(
                            Path(key[1]).is_relative_to(root) for root in current_roots[app])])
                    queue.db.execute("DELETE FROM usage_request_files WHERE (mtime_ns>0 AND mtime_ns<?) "
                                     "OR (mtime_ns=0 AND scanned_at<?)", (int(since * 1e9), since))
                    queue.db.execute("DELETE FROM usage_request_aliases WHERE happened_at<?", (since,))
                    usage.prune(queue.db)
        except InterruptedError:
            return False
    return True


def run_once(config, queue, stop, paused=lambda: False):
    history_complete = history_once(config, queue, stop, paused)
    return requests_once(config, queue, stop, paused) and history_complete


def run(config, queue, stop, paused=lambda: False, *, watch=False):
    from .config import Config

    while not stop.is_set():
        try:
            # CLI setup can record another profile after the service has started.
            # Recheck source paths without rescanning unchanged history.
            current = {**config, "hooks": Config.load(config.path).get("hooks", {})} if watch else config
            if run_once(current, queue, stop, paused) and not watch:
                return
        except Exception:
            # History is best effort and must never stop live collection. A
            # retry reuses stable record keys and the original import cutoff.
            pass
        stop.wait(30)
