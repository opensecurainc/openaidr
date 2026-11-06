"""Bounded metadata ledger and background estimation of captured hook events."""

from contextlib import closing
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time

from openaidr.core import hook_estimates as core
from openaidr.core.redact import redact_event


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS hook_estimates (
        scope TEXT NOT NULL, application TEXT NOT NULL, observation_id TEXT NOT NULL,
        observed_at REAL NOT NULL, model TEXT NOT NULL, model_source TEXT NOT NULL,
        estimated_input_tokens INTEGER NOT NULL, estimated_output_tokens INTEGER NOT NULL,
        estimated_cost_usd TEXT, modified INTEGER NOT NULL,
        PRIMARY KEY (scope,application,observation_id))""")
    db.execute("CREATE INDEX IF NOT EXISTS hook_estimates_time ON hook_estimates(scope,observed_at)")
    db.execute("CREATE INDEX IF NOT EXISTS hook_estimates_expiry ON hook_estimates(observed_at)")


def record(db, scope, export):
    for item in core.observations(export):
        db.execute("INSERT OR IGNORE INTO hook_estimates VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (scope, item["application"], item["observation_id"], item["observed_at"].timestamp(),
                    item["model"], item["model_source"], item["estimated_input_tokens"],
                    item["estimated_output_tokens"], str(item["estimated_cost_usd"])
                    if item["estimated_cost_usd"] is not None else None, int(item["modified"])))


def prune(db):
    db.execute("DELETE FROM hook_estimates WHERE observed_at<?", (time.time() - 30 * 86400,))
    excess = db.execute("SELECT count(*) FROM hook_estimates").fetchone()[0] - 100000
    if excess > 0:
        db.execute("""DELETE FROM hook_estimates WHERE rowid IN
            (SELECT rowid FROM hook_estimates ORDER BY observed_at,rowid LIMIT ?)""", (excess,))


def collect(telemetry, events):
    """Best effort, outside the hook decision path; no vendor API calls."""
    options = telemetry.config.get("telemetry") or {}
    estimates = options.get("hook_estimates") or {}
    if (not telemetry.options["enabled"] or not estimates.get("enabled", True)
            or telemetry.paused() or telemetry.auth_denied):
        return
    disabled = set(options.get("disabled_agents") or [])
    capture = telemetry.capture() if telemetry.capture is not None else None
    items = {}
    received = datetime.now(timezone.utc)
    for original in events:
        product = original.get("agent", {}).get("product")
        if (product not in core.PRODUCTS or product in disabled
                or (product == "github-copilot" and "copilot" in disabled)):
            continue
        # Managed observations belong to their journal and verified binding.
        # No separate estimate may escape that capture/export boundary.
        if "evidence" in original or original.get("session", {}).get("registration_id"):
            continue
        event = copy.deepcopy(original)
        if capture is not None:
            redact_event(event, capture)
        item = core.estimate(event, estimates.get("assumed_models"))
        if item and -300 <= (received - item["observed_at"]).total_seconds() <= 30 * 86400:
            items.setdefault((product, item["observation_id"]), item)
    if not items:
        return
    queue = telemetry.queue
    with queue.lock:
        fresh = [item for (app, ident), item in items.items() if not queue.db.execute(
            "SELECT 1 FROM hook_estimates WHERE scope=? AND application=? AND observation_id=?",
            (queue.usage_scope, app, ident)).fetchone()]
        if fresh:
            telemetry.accept("logs", json.dumps(core.payload(fresh)).encode(), "application/json")


def overview(config, since=None, until=None, *, timeout=1):
    until = until or datetime.now(timezone.utc)
    since = since or until - timedelta(days=30)
    rows = []
    path = Path(config["data_dir"]) / "telemetry.sqlite3"
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=timeout)) as db:
            db.row_factory = sqlite3.Row
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='hook_estimates'").fetchone():
                rows = db.execute("""SELECT application,model,model_source,count(*) AS observations,
                    count(estimated_cost_usd) AS priced_observations,
                    sum(CASE WHEN model_source='configured' THEN 1 ELSE 0 END) AS assumed_model_observations,
                    sum(modified) AS modified_observations,
                    sum(estimated_input_tokens) AS estimated_input_tokens,
                    sum(estimated_output_tokens) AS estimated_output_tokens,
                    sum(CAST(estimated_cost_usd AS REAL)) AS estimated_cost_usd
                    FROM (SELECT *,row_number() OVER (
                        PARTITION BY application,observation_id ORDER BY rowid) AS occurrence
                        FROM hook_estimates)
                    WHERE occurrence=1 AND observed_at>=? AND observed_at<=?
                    GROUP BY application,model,model_source""",
                    (since.timestamp(), until.timestamp())).fetchall()
    return dict(core.report(rows), since=since.isoformat(), until=until.isoformat())
