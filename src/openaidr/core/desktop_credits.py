"""Minimal customer credit data for the desktop, without service or provider details."""

import asyncio
from datetime import datetime, timedelta, timezone
import json

import httpx
from openaidr_api_client.client import IntelligenceClient
from openaidr_api_client.contracts.credits import amount, microcredits, utc


def project(value):
    if value is None:
        return None
    fields = {'status', 'allowance', 'used', 'reserved', 'available', 'starts_at', 'resets_at', 'checked_at'}
    if not isinstance(value, dict) or not fields <= value.keys():
        raise ValueError('Incomplete free usage')
    result = {key: value[key] for key in fields}
    checked = utc(result['checked_at'])
    age = (datetime.now(timezone.utc) - checked).total_seconds()
    if not -30 <= age <= 180:
        raise ValueError('Free usage is stale')
    amounts = [result[key] for key in ('allowance', 'used', 'reserved', 'available')]
    if result['status'] == 'disabled':
        if any(item is not None for item in (*amounts, result['starts_at'], result['resets_at'])):
            raise ValueError('Disabled free usage has no balance')
    elif result['status'] in ('active', 'exhausted'):
        total, used, reserved, available = map(microcredits, amounts)
        if not total or total != used + reserved + available or (result['status'] == 'exhausted') != (available == 0):
            raise ValueError('Free usage does not reconcile')
        if not utc(result['starts_at']) <= checked < utc(result['resets_at']):
            raise ValueError('Invalid free period')
    else:
        raise ValueError('Unknown free usage state')
    return result


async def fetch(connection, transport):
    # A fixed additive endpoint is not in the pinned SDK's route allowlist yet.
    # Keep its same bounded response, TLS, redirect and environment-proxy rules.
    async with asyncio.timeout(5):
        async with httpx.AsyncClient(base_url=connection.origin, transport=transport, verify=connection.verify(), trust_env=False,
                follow_redirects=False, timeout=5, headers={'Authorization':'Bearer ' + connection.api_key,
                'Accept-Encoding':'identity'}) as client:
            async with client.stream('GET', '/v1/free/usage') as response:
                response.raise_for_status()
                if response.status_code != 200 or response.headers.get('content-encoding', 'identity') != 'identity':
                    raise ValueError('Invalid free usage response')
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 4096:
                        raise ValueError('Free usage response exceeds limit')
    return json.loads(body)


def project_paid(value):
    fields = {'status', 'used', 'available', 'starts_at', 'checked_at'}
    if not isinstance(value, dict) or not fields <= value.keys():
        raise ValueError('Incomplete paid usage')
    result = {key: value[key] for key in fields}
    checked = utc(result['checked_at'])
    if not -30 <= (datetime.now(timezone.utc) - checked).total_seconds() <= 180:
        raise ValueError('Paid usage is stale')
    if result['status'] not in ('active', 'exhausted'):
        raise ValueError('Paid credits are unavailable')
    for key in ('used', 'available'):
        microcredits(result[key])
    if utc(result['starts_at']) != checked.replace(day=1, hour=0, minute=0, second=0, microsecond=0):
        raise ValueError('Invalid paid usage period')
    return result


def paid_usage(snapshot):
    checked = utc(snapshot.until)
    start = checked.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if snapshot.bucket_seconds != 86400 or utc(snapshot.since) > start:
        raise ValueError('Incomplete monthly credit window')
    rows = [row for row in snapshot.series if utc(row.time) >= start]
    expected = {start + timedelta(days=day) for day in range((checked - start).days + bool(checked.time() != start.time()))}
    if {utc(row.time) for row in rows} != expected:
        raise ValueError('Incomplete monthly credit buckets')
    # Settled charges are the usage total. Pending reservations remain separate.
    if any(row.credits_charged is None or row.unrated_operations for row in rows):
        raise ValueError('Monthly charges are not confirmed')
    return project_paid(dict(status=snapshot.status, used=amount(sum(microcredits(row.credits_charged) for row in rows)),
        available=snapshot.balance.available, starts_at=start.isoformat(), checked_at=snapshot.until))


async def read(connection, plan, *, transport=None):
    if plan == 'free':
        raw = await fetch(connection, transport)
        if not isinstance(raw, dict) or raw.get('tenant_id') != connection.tenant_id or raw.get('plan') != 'free':
            raise ValueError('Credit tenant mismatch')
        usage = project(raw.get('usage'))
        if usage is None:
            raise ValueError('Free credits are unknown')
    elif plan == 'paid':
        client = IntelligenceClient.from_connection(connection, transport=transport)
        try:
            usage = paid_usage(await client.credits('90d'))
        finally:
            await client.aclose()
    else:
        raise ValueError('Unknown credit plan')
    return dict(plan=plan, usage=usage)


def project_summary(value):
    if not isinstance(value, dict) or value.get('plan') not in ('free', 'paid'):
        raise ValueError('Unknown credit plan')
    usage = (project if value['plan'] == 'free' else project_paid)(value.get('usage'))
    if usage is None:
        raise ValueError('Credits are unknown')
    return dict(plan=value['plan'], usage=usage)
