"""Token and search accounting for model calls made by OpenAIDR services."""

from openaidr_api_client.contracts.usage import (
    parse_usage as parse_usage,
)

from datetime import datetime, timedelta, timezone
from .config import PLATFORM_AVAILABLE


RANGES = {"24h": (1, 3600), "7d": (7, 86400), "30d": (30, 86400), "90d": (90, 86400)}
PURPOSES = ("detection", "guardrail", "asset_management", "assistant", "verification", "benchmark")
if PLATFORM_AVAILABLE:
    from openaidr.platform.provider_settings import PRICE_DATE, RATES
else:
    PRICE_DATE, RATES = None, {}


def empty_totals():
    return dict(
        calls=0, usage_calls=0, priced_calls=0, unpriced_calls=0,
        pending_calls=0, failed_calls=0, input_tokens=None, output_tokens=None,
        tokens=None, cost_usd=None, web_search_calls=None,
    )


def configuration(st, tenant_id, *, inline_guardrails):
    """Name configured services without asserting worker readiness or repricing calls."""
    from .guardrail import inline as inline_guardrail
    from . import session_aggregation
    from .guardrail.scoring import MODEL
    from openaidr_api_client.validation.applications import MODEL as ASSET_MODEL
    from openaidr_api_client.validation.page_chat import MODEL as ASSISTANT_MODEL

    with st.transaction() as conn:
        guardrail = inline_guardrail.get_settings(st, tenant_id, conn=conn)
        investigator = session_aggregation.get_settings(st, tenant_id, conn=conn)
    return {
        "configured_models": {
            "detection": None,
            "guardrail": MODEL if inline_guardrails else None,
            "legacy_detection": None,
            "session_investigator": investigator["model"],
            "asset_management": ASSET_MODEL,
            "assistant": ASSISTANT_MODEL,
        },
        "configured_services": {
            "legacy_detection": {
                "model": None, "purpose": "detection", "scope": "retired", "tenant_enabled": False,
            },
            "guardrail": {
                "model": MODEL, "purpose": "guardrail", "tenant_enabled": guardrail["enabled"],
            },
            "session_investigator": {
                "model": investigator["model"], "purpose": "detection",
                "tenant_enabled": investigator["enabled"],
                "settings_version": investigator["version"],
                "detector_config_version": investigator["detector_config_version"],
            },
        },
    }


def overview(st, tenant_id, range_name="24h", purpose="", model=""):
    days, interval = RANGES[range_name]
    with st.transaction() as conn:
        until = conn.execute("SELECT now() AS time").fetchone()["time"]
        since = until - timedelta(days=days)
        rows = st.many(
            """WITH selected AS (
                SELECT *, floor(extract(epoch FROM started_at)/$4)::bigint*$4 AS bucket,
                    CASE WHEN model ~* '(jev|guardrail)' THEN 'guardrail' ELSE 'llm' END AS model_type
                FROM model_usage
                WHERE tenant_id=$1 AND started_at>=$2 AND started_at<$3
                  AND purpose=ANY($7)
                  AND ($5='' OR purpose=$5) AND ($6='' OR model=$6)
            )
            SELECT bucket, model, purpose, model_type, count(*) AS calls,
                count(input_tokens) AS usage_calls,
                count(cost_usd) AS priced_calls,
                count(*) FILTER (WHERE cost_usd IS NULL) AS unpriced_calls,
                count(*) FILTER (WHERE status='pending') AS pending_calls,
                count(*) FILTER (WHERE status='error') AS failed_calls,
                sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
                sum(input_tokens+output_tokens) AS tokens, sum(cost_usd) AS cost_usd,
                sum(web_search_calls) AS web_search_calls
            FROM selected
            GROUP BY GROUPING SETS ((), (bucket), (model), (purpose),
                (model_type), (model_type, purpose), (model_type, bucket),
                (model_type, bucket, purpose))""",
            tenant_id, since, until, interval, purpose, model, list(PURPOSES), conn=conn,
        )
    first = int(since.timestamp()) // interval * interval
    series = {stamp: empty_totals() for stamp in range(first, int(until.timestamp()) + 1, interval)}
    result = {
        "range": range_name, "since": since.isoformat(), "until": until.isoformat(),
        "currency": "USD", "bucket_seconds": interval,
        "summary": empty_totals(), "by_model": [], "by_purpose": [],
    }
    groups = {
        name: {
            "name": name, "summary": empty_totals(),
            "by_purpose": {purpose: empty_totals() for purpose in PURPOSES},
            "series": {
                stamp: {**empty_totals(), "by_purpose": {purpose: empty_totals() for purpose in PURPOSES}}
                for stamp in series
            },
        }
        for name in ("llm", "guardrail")
    }
    for row in rows:
        totals = {
            key: None if row[key] is None else float(row[key]) if key == "cost_usd" else int(row[key])
            for key in empty_totals()
        }
        if row["model_type"] is not None:
            group = groups[row["model_type"]]
            if row["bucket"] is not None:
                sample = group["series"][row["bucket"]]
                if row["purpose"] is not None:
                    sample["by_purpose"][row["purpose"]] = totals
                else:
                    sample.update(totals)
            elif row["purpose"] is not None:
                group["by_purpose"][row["purpose"]] = totals
            else:
                group["summary"] = totals
        elif row["bucket"] is not None:
            series[row["bucket"]] = totals
        elif row["model"] is not None:
            result["by_model"].append({"name": row["model"], **totals})
        elif row["purpose"] is not None:
            result["by_purpose"].append({"name": row["purpose"], **totals})
        else:
            result["summary"] = totals
    for key in ("by_model", "by_purpose"):
        result[key].sort(key=lambda row: (-(row["cost_usd"] or 0), row["name"]))
    result["series"] = [
        {"time": datetime.fromtimestamp(stamp, timezone.utc).isoformat(), **totals}
        for stamp, totals in sorted(series.items())
    ]
    for group in groups.values():
        group["by_purpose"] = [{"name": name, **totals} for name, totals in group["by_purpose"].items()]
        group["series"] = [
            {**sample, "time": datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
             "by_purpose": [{"name": name, **totals} for name, totals in sample["by_purpose"].items()]}
            for stamp, sample in group["series"].items()
        ]
    result["model_groups"] = list(groups.values())
    return result
