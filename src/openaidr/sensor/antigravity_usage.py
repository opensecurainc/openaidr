"""Quiet status-line adapter and private, bounded session usage snapshots."""

from contextlib import closing
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit

import httpx

from openaidr.core.agent_sessions import observations, report
from openaidr.core.agent_usage import number, token
from .config import Config


def payload(state):
    session = state.get("conversation_id") or state.get("session_id")
    if not isinstance(session, str) or not session or len(session) > 256:
        return None
    values = {"session.id": session}
    context = state.get("context_window") or {}
    for source, target in (("total_input_tokens", "session.input_tokens"),
                           ("total_output_tokens", "session.output_tokens")):
        value = token(context, source)
        if value is not None:
            values[target] = str(value)
    cost = number((state.get("cost") or {}).get("total_usd"))
    if cost is not None and cost <= 1_000_000_000:
        values["session.estimated_cost_usd"] = str(cost)
    if len(values) == 1:
        return None
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "antigravity-cli"}}]},
        "scopeLogs": [{"scope": {"name": "openaidr.antigravity"}, "logRecords": [{
            "eventName": "antigravity.session_usage", "timeUnixNano": str(time.time_ns()),
            "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in values.items()],
        }]}],
    }]}


def submit(config_path, stream):
    # The native status-line command must never print accounting, credentials,
    # errors or submitted content, nor affect permissions or execution.
    try:
        from .telemetry import settings
        config = Config.load(config_path)
        options = settings(config)
        if not options["enabled"] or "antigravity" in options.get("disabled_agents", []):
            return
        raw = stream.read(65537)
        if len(raw) > 65536:
            return
        body = payload(json.loads(raw))
        if body is None or unchanged(config, body):
            return
        endpoint = "http://" + options["listen"] + "/v1/logs"
        url = urlsplit(endpoint)
        if not ipaddress.ip_address(url.hostname).is_loopback or url.username or url.password:
            return
        with httpx.Client(timeout=1, trust_env=False, follow_redirects=False) as client:
            client.post(endpoint, json=body)
    except Exception:
        return


def unchanged(config, body):
    from .usage import local_identity
    path = Path(config["data_dir"]) / "telemetry.sqlite3"
    item, = observations(dict(payload=body, received_at=datetime.now(timezone.utc)))
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2)) as db:
            row = db.execute("""SELECT input_tokens,output_tokens,estimated_cost_usd FROM usage_sessions
                WHERE scope=? AND session_id=? AND observation_ns>?""",
                (local_identity(config), item["session_id"], time.time_ns() - 300 * 10**9)).fetchone()
            return row == (item["input_tokens"], item["output_tokens"], item["estimated_cost_usd"])
    except sqlite3.Error:
        return False


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS usage_sessions (
        scope TEXT NOT NULL, session_id TEXT NOT NULL, observation_ns INTEGER NOT NULL,
        input_tokens INTEGER, output_tokens INTEGER, estimated_cost_usd TEXT,
        PRIMARY KEY (scope,session_id))""")
    db.execute("CREATE INDEX IF NOT EXISTS usage_sessions_time ON usage_sessions(observation_ns)")


def record(db, scope, export):
    for item in observations(export):
        db.execute("""INSERT INTO usage_sessions VALUES (?,?,?,?,?,?)
            ON CONFLICT(scope,session_id) DO UPDATE SET
                observation_ns=excluded.observation_ns,input_tokens=excluded.input_tokens,
                output_tokens=excluded.output_tokens,estimated_cost_usd=excluded.estimated_cost_usd
            WHERE excluded.observation_ns>usage_sessions.observation_ns""",
            (scope, item["session_id"], item["observation_ns"], item["input_tokens"],
             item["output_tokens"], item["estimated_cost_usd"]))


def prune(db):
    db.execute("DELETE FROM usage_sessions WHERE observation_ns<?", (time.time_ns() - 30 * 86400 * 10**9,))
    db.execute("""DELETE FROM usage_sessions WHERE rowid IN
        (SELECT rowid FROM usage_sessions ORDER BY observation_ns DESC,rowid DESC LIMIT -1 OFFSET 10000)""")


def overview(config):
    path = Path(config["data_dir"]) / "telemetry.sqlite3"
    items = []
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
            db.row_factory = sqlite3.Row
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='usage_sessions'").fetchone():
                for row in db.execute("""SELECT * FROM (
                        SELECT *,row_number() OVER (PARTITION BY session_id ORDER BY observation_ns DESC,rowid DESC) AS occurrence
                        FROM usage_sessions WHERE observation_ns>?) WHERE occurrence=1
                        ORDER BY observation_ns DESC,session_id LIMIT 10000""",
                        (time.time_ns() - 30 * 86400 * 10**9,)):
                    items.append(dict(session_id=row["session_id"],
                        observed_at=datetime.fromtimestamp(row["observation_ns"] / 1e9, timezone.utc).isoformat(),
                        input_tokens=row["input_tokens"], output_tokens=row["output_tokens"],
                        estimated_cost_usd=row["estimated_cost_usd"]))
    return report(items)
