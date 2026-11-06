"""Read GitHub's explicit AI-credit or premium-request billing reports."""

from decimal import Decimal
import os
import re

import httpx

from .agent_billing import BillingError, amount, fetch_json, label, month, save

SCOPES = {"organization": "organizations", "enterprise": "enterprises", "user": "users"}
BASES = ("ai_credit", "premium_request")
AMOUNTS = ("pricePerUnit", "grossQuantity", "grossAmount", "discountQuantity", "discountAmount", "netQuantity", "netAmount")


def normalize(data, period):
    expected = month(period)
    if not isinstance(data, dict) or data.get("timePeriod") != {"year": expected.year, "month": expected.month}:
        raise BillingError("period_mismatch")
    items = data.get("usageItems")
    if not isinstance(items, list) or len(items) > 10000:
        raise BillingError("invalid_response")
    rows, excluded = [], 0
    for item in items:
        if not isinstance(item, dict):
            raise BillingError("invalid_response")
        product = label(item.get("product"))
        if product.casefold() not in ("copilot", "copilot ai credits"):
            excluded += 1
            continue
        rows.append({**{key: label(item.get(key)) for key in ("product", "sku", "model", "unitType")},
                     **{key: str(amount(item.get(key))) for key in AMOUNTS}})
    return dict(currency="USD", cost_kind="provider_reported_usage", usage_items=rows,
                gross_amount=str(sum((Decimal(row["grossAmount"]) for row in rows), Decimal(0))),
                discount_amount=str(sum((Decimal(row["discountAmount"]) for row in rows), Decimal(0))),
                net_amount=str(sum((Decimal(row["netAmount"]) for row in rows), Decimal(0))),
                excluded_product_rows=excluded,
                coverage="Reported Copilot usage after discounts; excludes seat subscriptions, tax and invoice adjustments. May change before billing closes.")


def fetch(scope, account, period, basis, token, *, client=None):
    stamp = month(period)
    path = f"https://api.github.com/{SCOPES[scope]}/{account}/settings/billing/{basis}/usage"
    if client is None:
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as http:
            return fetch(scope, account, period, basis, token, client=http)
    return normalize(fetch_json(client, "GET", path,
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"},
        params={"year": stamp.year, "month": stamp.month}), period)


def sync(st, tenant, scope, account, period, basis, *, client=None):
    if not tenant:
        raise ValueError("OPENAIDR_TENANT_ID is required")
    if scope not in SCOPES or basis not in BASES:
        raise ValueError("select a supported account scope and billing model")
    if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", account):
        raise ValueError("invalid GitHub account slug")
    month(period)
    source = dict(provider="copilot", scope=scope, account=account.lower(), basis=basis)
    attempted = st.scalar("SELECT clock_timestamp()")
    error, report = None, None
    try:
        token = os.environ.get("OPENAIDR_COPILOT_BILLING_TOKEN", "").strip()
        if not token:
            raise BillingError("missing_credential")
        if any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise BillingError("invalid_credential")
        report = fetch(scope, account, period, basis, token, client=client)
    except BillingError as exc:
        error = str(exc)
    save(st, tenant, source, period, attempted, report, error)
    return dict(status="failed" if error else "collected", error_code=error, source=source, period=period)
