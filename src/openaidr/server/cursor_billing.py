"""Read Cursor's paginated current-cycle member spending report."""

from datetime import datetime, timezone
from decimal import Decimal
import os
import re

import httpx

from .agent_billing import BillingError, amount, fetch_json, label, save


def integer(value):
    value = amount(value)
    if value != int(value):
        raise BillingError("invalid_response")
    return int(value)


def fetch(token, *, client=None):
    if client is None:
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as http:
            return fetch(token, client=http)
    members, expected = {}, None
    for page in range(1, 101):
        data = fetch_json(client, "POST", "https://api.cursor.com/teams/spend",
                          auth=httpx.BasicAuth(token, ""),
                          json=dict(page=page, pageSize=100, sortBy="user", sortDirection="asc"))
        if not isinstance(data, dict):
            raise BillingError("invalid_response")
        metadata = tuple(integer(data.get(key)) for key in ("subscriptionCycleStart", "totalMembers", "totalPages"))
        cycle, count, pages = metadata
        if cycle == 0 or count > 10000 or pages > 100 or (pages == 0 and count != 0):
            raise BillingError("invalid_response")
        if expected is not None and expected != metadata:
            raise BillingError("snapshot_changed")
        expected = metadata
        rows = data.get("teamMemberSpend")
        if not isinstance(rows, list) or len(rows) > 100:
            raise BillingError("invalid_response")
        for row in rows:
            if not isinstance(row, dict):
                raise BillingError("invalid_response")
            user = label(row.get("userId"))
            if user in members:
                raise BillingError("snapshot_changed")
            members[user] = dict(user_id=user, on_demand_usd=str(amount(row.get("spendCents")) / 100),
                                 overall_usage_usd=str(amount(row.get("overallSpendCents")) / 100))
        if page >= pages:
            if len(members) != count:
                raise BillingError("incomplete_response")
            try:
                start = datetime.fromtimestamp(cycle / 1000, timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                raise BillingError("invalid_response") from None
            return dict(currency="USD", cost_kind="provider_reported_usage", cycle_start=start,
                        members=list(members.values()),
                        on_demand_usd=str(sum((Decimal(row["on_demand_usd"]) for row in members.values()), Decimal(0))),
                        overall_usage_usd=str(sum((Decimal(row["overall_usage_usd"]) for row in members.values()), Decimal(0))),
                        account_binding="operator_label_for_credential_team",
                        coverage="Current-cycle members returned by Cursor. Overall usage includes included quota. Neither amount is a subscription-inclusive invoice. Pages are sampled during collection.")
    raise BillingError("response_too_large")


def sync(st, tenant, account, *, client=None):
    if not tenant:
        raise ValueError("OPENAIDR_TENANT_ID is required")
    if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", account):
        raise ValueError("provide a stable label for the Cursor team bound to this credential")
    source = dict(provider="cursor", scope="team", account=account.lower(), basis="current_cycle")
    attempted = st.scalar("SELECT clock_timestamp()")
    error, report = None, None
    try:
        token = os.environ.get("OPENAIDR_CURSOR_BILLING_TOKEN", "").strip()
        if not token:
            raise BillingError("missing_credential")
        if any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise BillingError("invalid_credential")
        report = fetch(token, client=client)
    except BillingError as exc:
        error = str(exc)
    save(st, tenant, source, "current", attempted, report, error)
    return dict(status="failed" if error else "collected", error_code=error, source=source, period="current")
