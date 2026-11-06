"""Read-only investigation accounting and settlement-delivery observations."""

from datetime import datetime, timedelta, timezone

import psycopg

from .httpx import APIError, require
from .store import Busy, now

SCOPE = "all_retained_investigation_connections"
METRICS = ("dispatch_pending", "unknown_usage", "unpriced_known_usage",
           "unacknowledged_settlement_decisions", "uncertain_transport")
QUERY_MILLISECONDS = 500
STALE = timedelta(minutes=5)
MAX_COUNT = (1 << 53) - 1


def _time(value):
    require(type(value) is str and len(value) <= 40, "invalid settlement timestamp")
    try:
        result = datetime.fromisoformat(value)
        require(result.tzinfo is not None, "settlement timestamp requires a time zone")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        require(False, "invalid settlement timestamp")


def validate(value, generated):
    """Only fixed aggregate fields can enter the signed reporting channel."""
    require(isinstance(value, dict) and set(value) == {"scope", "state", "reason", "observed_at", "data"},
            "invalid settlement observation")
    require(value["scope"] == SCOPE, "invalid settlement scope")
    if value["state"] == "unavailable":
        require(value["reason"] in ("query_timeout", "read_failed")
                and value["observed_at"] is None and value["data"] is None,
                "invalid unavailable settlement observation")
        return value
    require(value["state"] == "current" and value["reason"] == "ok", "invalid settlement state")
    observed = _time(value["observed_at"])
    require(generated - STALE <= observed <= generated + timedelta(seconds=5), "invalid settlement observation time")
    require(isinstance(value["data"], dict) and set(value["data"]) == set(METRICS), "invalid settlement metrics")
    for name, metric in value["data"].items():
        fields = {"count", "oldest_at"} | ({"deadline_elapsed_count"} if name == "dispatch_pending" else set())
        require(isinstance(metric, dict) and set(metric) == fields, "invalid settlement metric")
        count = metric["count"]
        require(type(count) is int and 0 <= count <= MAX_COUNT, "invalid settlement count")
        if count:
            oldest = _time(metric["oldest_at"])
            require(datetime(2020, 1, 1, tzinfo=timezone.utc) <= oldest <= observed, "invalid oldest settlement time")
        else:
            require(metric["oldest_at"] is None, "empty settlement metric has an observation")
        if name == "dispatch_pending":
            overdue = metric["deadline_elapsed_count"]
            require(type(overdue) is int and 0 <= overdue <= count, "invalid overdue dispatch count")
    return value


def unavailable(reason):
    return dict(scope=SCOPE, state="unavailable", reason=reason, observed_at=None, data=None)


def read_many(st, tenants):
    """No payload reads, accounting callbacks, row locks, cleanup, or writes."""
    if not tenants:
        return {}
    try:
        with st.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            conn.execute(f"SET LOCAL statement_timeout = '{QUERY_MILLISECONDS}ms'")
            rows = st.many("""WITH requests AS (
                SELECT a.tenant_id,r.state,r.dispatched_at,r.completed_at,a.deadline_at,u.cost_usd,
                    (u.input_tokens IS NULL OR u.output_tokens IS NULL OR u.cached_input_tokens IS NULL
                     OR u.cache_write_input_tokens IS NULL) AS usage_unknown
                FROM session_investigation_requests r
                JOIN session_investigation_attempts a ON a.id=r.attempt_id
                LEFT JOIN model_usage u ON u.id=r.usage_id AND u.tenant_id=a.tenant_id
                WHERE a.tenant_id=ANY($1::uuid[])
            ), totals AS (
                SELECT tenant_id,
                    count(*) FILTER(WHERE state='dispatched') AS dispatch_pending,
                    min(dispatched_at) FILTER(WHERE state='dispatched') AS dispatch_pending_at,
                    count(*) FILTER(WHERE state='dispatched' AND deadline_at<=statement_timestamp()) AS overdue,
                    count(*) FILTER(WHERE state<>'dispatched' AND usage_unknown) AS unknown_usage,
                    min(completed_at) FILTER(WHERE state<>'dispatched' AND usage_unknown) AS unknown_usage_at,
                    count(*) FILTER(WHERE state<>'dispatched' AND NOT usage_unknown AND cost_usd IS NULL) AS unpriced_known_usage,
                    min(completed_at) FILTER(WHERE state<>'dispatched' AND NOT usage_unknown AND cost_usd IS NULL) AS unpriced_known_usage_at,
                    count(*) FILTER(WHERE state='uncertain') AS uncertain_transport,
                    min(completed_at) FILTER(WHERE state='uncertain') AS uncertain_transport_at
                FROM requests GROUP BY tenant_id
            ), decisions AS (
                SELECT b.tenant_id,count(*) AS unacknowledged_settlement_decisions,
                    min(m.created_at) AS unacknowledged_settlement_decisions_at
                FROM session_investigation_remote_messages m
                JOIN session_investigation_remote_bindings b ON b.attempt_id=m.attempt_id
                WHERE b.tenant_id=ANY($1::uuid[]) AND m.operation_kind='finish_call' AND m.ack_revision IS NULL
                GROUP BY b.tenant_id
            ) SELECT selected.tenant_id,statement_timestamp() AS observed_at,
                totals.dispatch_pending,totals.dispatch_pending_at,totals.overdue,
                totals.unknown_usage,totals.unknown_usage_at,
                totals.unpriced_known_usage,totals.unpriced_known_usage_at,
                totals.uncertain_transport,totals.uncertain_transport_at,
                decisions.unacknowledged_settlement_decisions,decisions.unacknowledged_settlement_decisions_at
                FROM unnest($1::uuid[]) AS selected(tenant_id)
                LEFT JOIN totals USING(tenant_id) LEFT JOIN decisions USING(tenant_id)""", tenants, conn=conn)
        result = {}
        for row in rows:
            data = {name: dict(count=row[name] or 0,
                               oldest_at=row[name + "_at"].isoformat() if row[name + "_at"] else None)
                    for name in METRICS}
            data["dispatch_pending"]["deadline_elapsed_count"] = row["overdue"] or 0
            result[row["tenant_id"]] = validate(dict(scope=SCOPE, state="current", reason="ok",
                observed_at=row["observed_at"].isoformat(), data=data), row["observed_at"])
        return result
    except psycopg.errors.QueryCanceled:
        reason = "query_timeout"
    except (psycopg.Error, Busy, OSError, APIError):
        reason = "read_failed"
    return {tenant: unavailable(reason) for tenant in tenants}


def view(value=None, *, attempted_at=None, received_at=None, at=None):
    """Age retained readings at their own observation time, never the cost range."""
    at = at or now()
    observed = _time(value["observed_at"]) if value and value["observed_at"] else None
    state = value["state"] if value else "unsupported"
    if state == "current" and (observed is None or at - observed > STALE or observed > at + timedelta(seconds=5)):
        state = "stale"
    data = None
    if value and value["data"] is not None:
        data = {name: {**metric, "oldest_age_seconds":
                       (observed - _time(metric["oldest_at"])).total_seconds() if metric["oldest_at"] else None}
                for name, metric in value["data"].items()}
    return dict(scope=SCOPE, collection_state=state, reason=value["reason"] if value else "unsupported",
                fresh=state == "current", observed_at=observed, attempted_at=attempted_at,
                received_at=received_at, data=data)
