"""Provider billing snapshots with explicit freshness and failure status."""

from datetime import date
from decimal import Decimal
import json
import re

import httpx
from psycopg.types.json import Jsonb

from openaidr.core.agent_usage import number


class BillingError(ValueError):
    """Only fixed error codes may cross the provider boundary."""


def month(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}", value, flags=re.ASCII):
        raise ValueError("month must be YYYY-MM")
    try:
        return date.fromisoformat(value + "-01")
    except ValueError:
        raise ValueError("month must be YYYY-MM") from None


def amount(value):
    result = number(value)
    if result is None:
        raise BillingError("invalid_response")
    return result


def label(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise BillingError("invalid_response")
    return value


def fetch_json(client, method, url, **kwargs):
    try:
        with client.stream(method, url, **kwargs) as response:
            if response.status_code != 200:
                raise BillingError("provider_http_" + str(response.status_code))
            body = bytearray()
            for part in response.iter_bytes():
                body.extend(part)
                if len(body) > 8 << 20:
                    raise BillingError("response_too_large")
            return json.loads(body, parse_float=Decimal)
    except (httpx.HTTPError, OSError):
        raise BillingError("provider_unavailable") from None
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise BillingError("invalid_response") from None


def save(st, tenant, source, period, attempted, report=None, error=None):
    # A slower, earlier poll must not overwrite a newer success or failure.
    st.execute("""INSERT INTO agent_billing_reports
        (tenant_id,provider,account_scope,account,period,basis,attempted_at,collected_at,error_code,report)
        VALUES ($1,$2,$3,$4,$5,$6,$7,CASE WHEN $8::text IS NULL THEN clock_timestamp() END,$8,$9)
        ON CONFLICT(tenant_id,provider,account_scope,account,period,basis) DO UPDATE SET
            attempted_at=excluded.attempted_at,error_code=excluded.error_code,
            collected_at=CASE WHEN excluded.error_code IS NULL THEN excluded.collected_at ELSE agent_billing_reports.collected_at END,
            report=CASE WHEN excluded.error_code IS NULL THEN excluded.report ELSE agent_billing_reports.report END
        WHERE excluded.attempted_at>=agent_billing_reports.attempted_at""",
        tenant, source["provider"], source["scope"], source["account"], period, source["basis"],
        attempted, error, Jsonb(report) if report is not None else None)


def overview(st, tenant, provider=""):
    rows = st.many("""SELECT provider,account_scope,account,period,basis,attempted_at,collected_at,error_code,report
        FROM agent_billing_reports WHERE tenant_id=$1 AND ($2='' OR provider=$2)
        ORDER BY attempted_at DESC,provider,account_scope,account,period,basis LIMIT 101""", tenant, provider)
    return dict(items=[dict(row, attempted_at=row["attempted_at"].isoformat(),
                           collected_at=row["collected_at"].isoformat() if row["collected_at"] else None,
                           status="failed" if row["error_code"] else "collected") for row in rows[:100]],
                truncated=len(rows) > 100,
                coverage="Separate provider usage reports. Do not add overlapping account scopes, billing models, request estimates or subscription fees.")
