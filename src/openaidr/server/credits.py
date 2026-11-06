"""Customer credit accounting comes only from the selected Intelligence API."""

from datetime import datetime, timedelta, timezone

import httpx

from openaidr_api_client.client import SyncIntelligenceClient, Unavailable

from .model_keys import selected_connection


RANGES = {"24h": (1, 3600), "30d": (30, 86400), "90d": (90, 86400)}


def unavailable(tenant, range_name):
    days, bucket = RANGES[range_name]
    until = datetime.now(timezone.utc)
    return {
        "schema_version": 1,
        "tenant_id": tenant,
        "status": "unavailable",
        "rate_version": None,
        "credits_per_usd": "100",
        "since": (until - timedelta(days=days)).isoformat(),
        "until": until.isoformat(),
        "bucket_seconds": bucket,
        "balance": {"available": None, "reserved": None},
        "summary": {"credits_charged": None, "operations": 0,
                    "pending_operations": 0, "unrated_operations": 0},
        "by_service": [],
        "series": [],
    }


def overview(tenant, cfg, range_name="24h", *, st=None):
    client = None
    try:
        connection = selected_connection(cfg, st)
        if connection is None or connection.tenant_id != tenant:
            return unavailable(tenant, range_name)
        client = SyncIntelligenceClient.from_connection(connection)
        snapshot = client.credits(range_name)
        if snapshot.tenant_id != tenant:
            raise ValueError("Credit tenant mismatch")
        return snapshot.model_dump()
    except (Unavailable, httpx.HTTPError, TimeoutError, OSError, ValueError):
        # Provider accounting in retained tenant records is never a fallback for
        # a missing customer ledger. Error bodies may contain private metadata.
        return unavailable(tenant, range_name)
    finally:
        if client is not None:
            client.close()
