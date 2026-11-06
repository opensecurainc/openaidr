"""Dormant recovery of one persisted complete investigation; no job admission."""

from contextlib import closing

import httpx
from psycopg.types.json import Jsonb
from openaidr_api_client.client import SyncIntelligenceClient, Unavailable
from openaidr_api_client.contracts.errors import APIError

from . import intelligence, investigation_submissions as submissions
from . import session_aggregation as aggregation, session_investigator as inv


def _row(st, tenant, ident, *, conn=None):
    return st.one("""SELECT b.*,a.job_id,a.claim_token,r.state AS billing_state FROM session_investigation_submissions b
        JOIN session_investigation_attempts a ON a.id=b.attempt_id AND a.tenant_id=b.tenant_id
        JOIN session_investigation_jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
        LEFT JOIN service_credit_receipts r ON r.tenant_id=b.tenant_id AND r.request_id=b.attempt_id
        WHERE b.tenant_id=$1 AND b.attempt_id=$2 AND j.protocol_version=4""", tenant, ident, conn=conn)


def _claim(row):
    return {key: row[key] for key in ("tenant_id", "job_id", "attempt_id", "claim_token")}


def _sources(request):
    return [item["session_id"] for item in (request.get("history") or {}).get("sessions", [])]


def _touch(st, row, code, *, cancel=False):
    st.execute("""UPDATE session_investigation_submissions SET checked_at=clock_timestamp(),last_error=$3,
        cancel_requested=cancel_requested OR $4 WHERE tenant_id=$1 AND attempt_id=$2 AND publication IS NULL""",
        row["tenant_id"], row["attempt_id"], code, cancel)


def _reads(st, c, request, receipts):
    sessions = {item["session_id"]: item for item in (request.get("history") or {}).get("sessions", [])}
    for receipt in receipts:
        inv._checkpoint(c)
        response = receipt["response"]
        source = sessions.get(response["session_id"])
        inv._need(source is not None and source["snapshot_id"] == response["version"]["snapshot_id"], "invalid_result")
        inv._need(all(response["coverage"].get(key) == source["coverage"].get(key) for key in ("status", "gaps")),
                  "invalid_result")
        wire = submissions._contracts()
        inv._need(wire.stamp(request["history"]["end_at"]) <= wire.stamp(response["version"]["observed_at"])
                  <= wire.stamp(request["deadline_at"]), "invalid_result")
        for fragment in response["items"]:
            inv._need(1 <= fragment["ordinal"] <= len(source["items"]), "invalid_result")
            item = source["items"][fragment["ordinal"] - 1]
            raw = wire.canonical(item)
            inv._need(fragment["source_id"] == item["source_id"] and fragment["total_bytes"] == len(raw)
                      and raw[fragment["start"]:fragment["end"]] == fragment["text"].encode(), "invalid_result")
        authority = c["sources"].get(source["session_id"])
        inv._need(authority is not None, "scope_unavailable")
        st.execute("""INSERT INTO session_investigation_reads
            (id,attempt_id,submission_id,tool_call_id,tool_name,arguments,status,session_id,
             source_registration_id,source_sensor_id,source_snapshot_id,response,response_sha256)
            VALUES($1,$2,$2,$1,'read_session',$3,'delivered',$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO NOTHING""",
            receipt["id"], c["attempt"]["id"], Jsonb(receipt["arguments"]), source["session_id"],
            authority["registration_id"], authority["sensor_id"], source["snapshot_id"], Jsonb(response),
            wire.digest(response), conn=c["conn"])
        stored = st.one("SELECT attempt_id,submission_id,response_sha256 FROM session_investigation_reads WHERE id=$1",
                        receipt["id"], conn=c["conn"])
        inv._need(stored["attempt_id"] == stored["submission_id"] == c["attempt"]["id"]
                  and stored["response_sha256"] == wire.digest(response), "invalid_result")


def _publish(st, row, connection, request, remote):
    wire = submissions._contracts()
    # The public contract fixes expiry at one hour after completion. Retrieval
    # may be late, but inference must have completed within its original grant.
    inv._need(wire.stamp(remote["expires_at"]) - 3600 <= wire.stamp(request["deadline_at"]), "invalid_result")
    with inv._fence(st, _claim(row), sources=_sources(request), allow_expired=True) as c:
        inv._need(all(c["sources"].values()), "scope_unavailable")
        current = st.one("SELECT * FROM session_investigation_submissions WHERE attempt_id=$1 FOR UPDATE",
                         row["attempt_id"], conn=c["conn"])
        submissions.bound_request(current, connection)
        if current["publication"] is not None:
            return
        inv._need(not current["cancel_requested"] and current["closed_at"] is None
                  and current["remote_status"] == "completed", "cancelled")
        _reads(st, c, request, remote["result"]["reads"])
        result = inv._validate_result(st, c, None, remote["result"]["report"], submitted=request)
        coverage = dict(status="complete", target_item_count=request["target"]["item_count"],
            target_byte_count=sum(len(wire.canonical(item)) for item in request["target"]["items"]), gaps=result["gaps"])
        publication = inv._publish_validated(st, c, coverage, result)
        st.execute("""UPDATE session_investigation_submissions SET publication=$2,closed_at=clock_timestamp()
            WHERE attempt_id=$1""", row["attempt_id"], Jsonb(publication), conn=c["conn"])


def _stop(st, row, code):
    with st.transaction() as conn:
        inv.stop_attempt(st, _claim(row), code, conn=conn)
        st.execute("""UPDATE session_investigation_submissions SET closed_at=clock_timestamp(),last_error=$3
            WHERE tenant_id=$1 AND attempt_id=$2 AND publication IS NULL""",
            row["tenant_id"], row["attempt_id"], code, conn=conn)


def reconcile(st, config, tenant, attempt_id, *, transport=None):
    """Recover one identity using its origin's current key, independently of selection.

    HTTP errors and missing credentials leave accounting unresolved. A 404 is
    never proof of no charge: service metadata can expire after acceptance.
    """
    wire = submissions._contracts()
    row = _row(st, tenant, attempt_id)
    if (row["closed_at"] is not None and row["remote_status"] in wire.TERMINAL
            and row["billing_state"] in ("disabled", "settled", "released")):
        return False
    try:
        connection = intelligence.connection_for_origin(config, st, row["origin"])
    except (APIError, ValueError):
        connection = None
    if connection is None:
        _touch(st, row, "credentials_unavailable")
        return True
    request = submissions.bound_request(row, connection)
    cancelled = row["cancel_requested"] or row["closed_at"] is not None and row["publication"] is None
    if row["publication"] is None and not cancelled:
        try:
            with inv._fence(st, _claim(row), sources=_sources(request), allow_expired=True) as c:
                inv._need(all(c["sources"].values()), "scope_unavailable")
        except (inv.InvestigationStopped, ValueError) as error:
            if getattr(error, "code", None) == "internal_error":
                _touch(st, row, "internal_error")
                return True
            cancelled = True
    if cancelled:
        _touch(st, row, "cancelled", cancel=True)
    parsed = None
    try:
        with closing(SyncIntelligenceClient.from_connection(connection, transport=transport)) as client:
            try:
                raw = client.request("/v1/investigations/" + attempt_id, None, wire.MAX_BODY, 10, method="GET")
            except Unavailable as error:
                if error.status_code != 404:
                    raise
                raw = None
                current = _row(st, tenant, attempt_id)
                if current["remote_status"] == "completed":
                    if current["closed_at"] is None and current["publication"] is None:
                        _stop(st, current, "result_unavailable")
                    return True
                _touch(st, row, "status_unavailable")
                remaining = wire.stamp(request["deadline_at"]) - st.scalar("SELECT clock_timestamp()").timestamp()
                if not cancelled and remaining > 0 and row["remote_id"] is None:
                    with inv._fence(st, _claim(row), sources=_sources(request)) as c:
                        current = _row(st, tenant, attempt_id, conn=c["conn"])
                        inv._need(all(c["sources"].values()) and not current["cancel_requested"]
                                  and current["closed_at"] is None, "scope_unavailable")
                        inv._need(aggregation._job_current(st, c["job"], c["settings"], c["conn"])
                                  and aggregation._threshold_matches(st, c["job"], c["settings"], c["conn"]),
                                  "settings_changed")
                    remaining = wire.stamp(request["deadline_at"]) - st.scalar("SELECT clock_timestamp()").timestamp()
                    inv._need(remaining > 0, "claim_expired")
                    raw = client.request("/v1/investigations", request, wire.MAX_BODY, min(10, remaining),
                                         accepted_status=(200, 202), request_id=attempt_id)
            if raw is not None:
                try:
                    parsed = submissions.record(st, tenant, attempt_id, connection, raw)
                except ValueError:
                    cancelled = True
                    _touch(st, row, "service_contract_violation", cancel=True)
            if (parsed is not None and parsed["status"] not in wire.TERMINAL
                    and st.scalar("SELECT clock_timestamp()").timestamp() >= wire.stamp(request["deadline_at"])):
                cancelled = True
                _touch(st, row, "claim_expired", cancel=True)
            if cancelled and (parsed is None or parsed["status"] not in wire.TERMINAL):
                raw = client.request("/v1/investigations/" + attempt_id + "/cancel", {}, wire.MAX_BODY, 10,
                                     accepted_status=(200, 202))
                parsed = submissions.record(st, tenant, attempt_id, connection, raw)
        current = _row(st, tenant, attempt_id)
        if current["publication"] is not None or current["closed_at"] is not None:
            return True
        if parsed is None:
            if current["remote_status"] == "completed" and current["last_error"] == "invalid_result":
                _stop(st, current, "invalid_result")
            return True
        if parsed["status"] in wire.TERMINAL:
            if parsed["status"] == "completed" and parsed["result"] is not None and not cancelled:
                _publish(st, current, connection, request, parsed)
            else:
                _stop(st, current, "cancelled" if cancelled else (parsed["error"] or {}).get("code", "service_unavailable"))
    except (Unavailable, httpx.HTTPError, TimeoutError, OSError):
        _touch(st, row, "service_unavailable")
    except (inv.InvestigationStopped, ValueError) as error:
        current = _row(st, tenant, attempt_id)
        if current["publication"] is None:
            code = getattr(error, "code", "invalid_result")
            _touch(st, current, code, cancel=code != "internal_error")
            if code != "internal_error" and current["remote_status"] in wire.TERMINAL:
                _stop(st, current, code)
    return True
