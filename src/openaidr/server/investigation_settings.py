"""Dormant customer settings receiver for complete investigation jobs."""

from contextlib import nullcontext

from openaidr_api_client.contracts.credits import amount, microcredits

from . import investigation_submissions, session_aggregation as aggregation
from .httpx import APIError, require


PROVIDER_FIELDS = frozenset(("model", "max_tokens_per_attempt", "max_cost_usd_per_attempt", "hourly_tokens", "hourly_cost_usd"))
CREDITS = ("max_credits_per_attempt", "hourly_credits", "weekly_credits")
FIELDS = tuple(key for key in aggregation.SETTINGS if key not in PROVIDER_FIELDS) + CREDITS
DETECTOR_FIELDS = ("max_runtime_seconds", "history_days", *CREDITS)


def _view(row):
    value = {name: amount(row[name + "_microcredits"]) if row[name + "_microcredits"] is not None else None for name in CREDITS}
    return {**aggregation._settings_view({key: row[key] for key in FIELDS if key not in CREDITS}), **value,
            **{key: row[key] for key in ("version", "detector_config_version", "updated_at")}}


def read(st, tenant_id, conn=None):
    investigation_submissions._contracts()
    return _view(st.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", tenant_id, conn=conn))


def save(st, tenant_id, payload, actor, *, expected_version=None, conn=None):
    """Explicitly convert only future jobs; retain old rows and provider values.

    No route invokes this receiver until the complete-job controller and the
    coordinated SDK activation are available. Conversion is never inferred from
    an installed SDK, a model name, a credit balance, or an old job's contents.
    """
    investigation_submissions._contracts()
    aggregation._body(payload, FIELDS, ("enabled",))
    require(type(payload["enabled"]) is bool, "enabled must be a boolean")
    with nullcontext(conn) if conn is not None else st.transaction() as conn:
        st.execute("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "session-detection-settings:" + tenant_id, conn=conn)
        old = st.one("SELECT * FROM tenant_session_detection_settings WHERE tenant_id=$1", tenant_id, conn=conn)
        previous = _view(old)
        require(expected_version is None or previous["version"] == expected_version,
                "Investigation settings changed. Refresh and try again.", 409)
        values = {name: payload.get(name, previous[name]) for name in FIELDS}
        for name in CREDITS:
            if values[name] is not None:
                try:
                    values[name] = amount(microcredits(values[name]))
                except (ValueError, TypeError):
                    raise APIError(400, "invalid " + name) from None
        require((values[CREDITS[0]] is None) == (values[CREDITS[1]] is None), "Set both customer credit limits or leave both unset")
        require(values[CREDITS[0]] is None or microcredits(values[CREDITS[1]]) >= microcredits(values[CREDITS[0]]),
                "hourly_credits is below max_credits_per_attempt")
        require(values["weekly_credits"] is None or values["max_credits_per_attempt"] is None
                or microcredits(values["weekly_credits"]) >= microcredits(values["max_credits_per_attempt"]),
                "weekly_credits is below max_credits_per_attempt")
        required = {key: value for key, value in values.items() if key != "weekly_credits"}
        aggregation._validate_settings(required)
        values.update(required)
        changed = old["job_protocol_version"] != 4 or any(values[key] != previous[key] for key in DETECTOR_FIELDS)
        columns = {name + "_microcredits" if name in CREDITS else name:
                   microcredits(value) if name in CREDITS and value is not None else value for name, value in values.items()}
        row = aggregation._persist_settings(st, tenant_id, {**columns, "job_protocol_version": 4}, actor, changed, conn,
                                             audit_values=values)
        return _view(row)
