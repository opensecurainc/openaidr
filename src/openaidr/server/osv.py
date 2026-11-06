"""Bounded OSV queries and tenant-scoped cached package assessments."""

from openaidr_api_client.validation.osv import (
    REFRESH as REFRESH,
    BATCH as BATCH,
    MAX_ADVISORIES as MAX_ADVISORIES,
    MAX_RESPONSE as MAX_RESPONSE,
    MAX_QUERY_PAGES as MAX_QUERY_PAGES,
    MAX_NAME as MAX_NAME,
    MAX_VERSION as MAX_VERSION,
    MAX_SUMMARY as MAX_SUMMARY,
    MAX_VECTORS as MAX_VECTORS,
    MAX_VECTOR_SCORE as MAX_VECTOR_SCORE,
    NPM_NAME as NPM_NAME,
    _NUMBER as _NUMBER,
    _PRERELEASE as _PRERELEASE,
    NPM_VERSION as NPM_VERSION,
    PYPI_NAME as PYPI_NAME,
    PYPI_VERSION as PYPI_VERSION,
    ID as ID,
    KEY_FIELDS as KEY_FIELDS,
    package_query as package_query,
    Unavailable as Unavailable,
)

import asyncio
import json
import logging
from datetime import timedelta
from uuid import uuid4

import httpx
from psycopg.types.json import Jsonb
from starlette.concurrency import run_in_threadpool

from .store import now

log = logging.getLogger(__name__)
RETRY = timedelta(minutes=15)
# Only confirmed failed dispatches release a scope for retry. This predicate
# refers to the original inventory claim, not a newly selected connection.
HELD_CLAIM = """EXISTS (SELECT 1 FROM service_call_intents i
    WHERE i.tenant_id=p.tenant_id AND i.scope_id=p.claim_token
      AND i.service='package_vulnerabilities' AND i.outcome IS DISTINCT FROM 'failed')"""


def claim(st, tenant=""):
    stamp, token = now(), str(uuid4())
    # Short claims let multiple detection processes share work without holding a
    # database connection during an external request. Expired legacy claims
    # recover; a customer dispatch without a usable result retains its scope.
    rows = st.many(f"""SELECT DISTINCT c.tenant_id,c.ecosystem,c.identifier,c.version
        FROM inventory_components c JOIN sensors s ON s.id=c.sensor_id AND s.tenant_id=c.tenant_id
        LEFT JOIN inventory_osv_packages p ON p.tenant_id=c.tenant_id AND p.ecosystem=c.ecosystem
            AND p.identifier=c.identifier AND p.version=c.version
        WHERE c.kind='package' AND c.ecosystem IN ('npm','pypi') AND s.deleted_at IS NULL
            AND ($1::uuid IS NULL OR c.tenant_id=$1::uuid)
            AND length(c.identifier)<=214 AND c.identifier ~ '^[A-Za-z0-9@._/-]+$'
            AND length(c.version)<=256 AND c.version ~ '^[A-Za-z0-9.!_+-]+$'
            AND (p.next_check_at IS NULL OR p.next_check_at<=$2)
            AND NOT {HELD_CLAIM}
        ORDER BY c.tenant_id,c.ecosystem,c.identifier,c.version LIMIT $3""", tenant or None, stamp, BATCH)
    claimed = []
    with st.transaction() as conn:
        for row in rows:
            # Admission locks this same row before recording its intent. Take
            # that lock first so the following statement sees any committed
            # intent after waiting, rather than using the old UPSERT snapshot.
            st.many("""SELECT claim_token FROM inventory_osv_packages
                WHERE tenant_id=$1 AND ecosystem=$2 AND identifier=$3 AND version=$4 FOR UPDATE""",
                row["tenant_id"], *(row[field] for field in KEY_FIELDS), conn=conn)
            values = st.many(f"""INSERT INTO inventory_osv_packages AS p
                (tenant_id,ecosystem,identifier,version,next_check_at,claim_token,attempted_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (tenant_id,ecosystem,identifier,version) DO UPDATE
                SET next_check_at=EXCLUDED.next_check_at,claim_token=EXCLUDED.claim_token,attempted_at=EXCLUDED.attempted_at
                WHERE p.next_check_at <= $7 AND NOT {HELD_CLAIM} RETURNING *""",
                row["tenant_id"], *(row[field] for field in KEY_FIELDS), stamp + timedelta(minutes=2), token, stamp, conn=conn)
            claimed.extend(values)
    return claimed


def save(st, row, findings, error="", *, checked_at=None, expires_at=None, conn=None):
    stamp = now()
    return st.execute(f"""UPDATE inventory_osv_packages AS p SET
        findings=CASE WHEN $6='' THEN $5::jsonb ELSE findings END,
        checked_at=CASE WHEN $6='' THEN $7 ELSE checked_at END,
        error=CASE WHEN $6<>'' AND {HELD_CLAIM}
            THEN 'OSV check unavailable; previous request has no usable result' ELSE $6 END,
        next_check_at=$8,
        claim_token=CASE WHEN $6<>'' AND {HELD_CLAIM} THEN p.claim_token ELSE NULL END
        WHERE tenant_id=$1 AND ecosystem=$2 AND identifier=$3 AND version=$4 AND claim_token=$9""",
        row["tenant_id"], *(row[field] for field in KEY_FIELDS), Jsonb(findings), error, checked_at or stamp,
        stamp + RETRY if error else expires_at or (checked_at or stamp) + REFRESH, row["claim_token"], conn=conn)


async def tick(st, intelligence, tenant="", *, customer=False):
    if customer:
        from .service_osv import tick as customer_tick

        return await customer_tick(st, intelligence, tenant)
    if intelligence is None:
        return False
    if str(tenant) != intelligence.tenant_id:
        raise Unavailable("Intelligence worker requires its bound tenant")
    rows = await run_in_threadpool(claim, st, tenant)
    if not rows:
        return False
    queries, indices = [], {}
    for row in rows:
        query, reason = package_query(row)
        if query is None:
            # Invalid identities are never submitted. They remain unassessed in
            # API reads and receive a long retry interval in the work cache.
            await run_in_threadpool(save, st, row, [])
            continue
        identity = json.dumps(query, sort_keys=True)
        if identity not in indices:
            indices[identity] = len(queries)
            queries.append(query)
    if not queries:
        return True
    failures = (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError, TimeoutError, Unavailable)
    assessments = None
    try:
        async with asyncio.timeout(30):
            assessments = await intelligence.packages(queries)
            results = [item["findings"] if item["status"] == "complete" else None for item in assessments]
    except failures:
        results = [None] * len(queries)
    for row in rows:
        query = package_query(row)[0]
        if query is not None:
            index = indices[json.dumps(query, sort_keys=True)]
            findings = results[index]
            assessment = assessments[index] if assessments is not None else {}
            await run_in_threadpool(save, st, row, findings or [],
                                    "OSV check unavailable; retry scheduled" if findings is None else "",
                                    checked_at=assessment.get("checked_at"), expires_at=assessment.get("expires_at"))
    return True


async def run(st, stop, tenant="", *, intelligence=None, customer=False):
    if intelligence is None:
        return
    while not stop.is_set():
        try:
            worked = await tick(st, intelligence, tenant, customer=customer)
        except Exception:
            log.warning("Inventory vulnerability assessment unavailable")
            worked = False
        try:
            await asyncio.wait_for(stop.wait(), timeout=1 if worked else 60)
        except TimeoutError:
            pass


def enrich(st, tenant, rows, enabled=True):
    identities = [dict(zip(KEY_FIELDS, (row.get(field, "") for field in KEY_FIELDS)))
                  for row in rows if package_query(row)[0] is not None]
    cached = st.many("""SELECT p.* FROM inventory_osv_packages p
        JOIN jsonb_to_recordset($2::jsonb) AS q(ecosystem text,identifier text,version text)
        ON p.ecosystem=q.ecosystem AND p.identifier=q.identifier AND p.version=q.version
        WHERE p.tenant_id=$1""", tenant, Jsonb(identities)) if identities and enabled else []
    by_key = {tuple(row[field] for field in KEY_FIELDS): row for row in cached}
    stamp = now()
    for row in rows:
        query, reason = package_query(row)
        value = {"provider": "OSV", "status": "not_assessed", "reason": reason,
                 "checked_at": None, "findings": []}
        if not enabled:
            value["reason"] = "Vulnerability checks are disabled"
        elif query:
            value.update(status="pending", reason="Vulnerability check pending")
            prior = by_key.get(tuple(row[field] for field in KEY_FIELDS))
            if prior:
                checked = prior["checked_at"]
                status = ("unavailable" if prior["error"] else "pending" if checked is None
                          else "stale" if checked + REFRESH <= stamp else "complete")
                value.update(status=status, checked_at=checked, findings=prior["findings"],
                             reason=prior["error"] or ("Vulnerability check pending" if status == "pending"
                                                      else "Assessment needs refresh" if status == "stale" else ""))
        row["vulnerability"] = value
