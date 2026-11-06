"""Analyst cases over retained investigation snapshots and reported identities."""

from .customer_views import investigation_report

from datetime import date, datetime, time, timedelta, timezone
from hashlib import sha256
from html import escape
import json
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from psycopg.types.json import Jsonb

from . import risk_activity
from .httpx import require
from .session_aggregation import get_settings
from .session_operator import _json_safe, _read, _uuid
from .store import Conflict, new_id

OUTCOMES = {"review": "Under review", "tp": "True positive", "fp": "False positive"}
PAGE_SIZE = 5

# Scores always come from the case's retained snapshots, never today's live
# session aggregate. User cases collect reports; they do not invent a new model
# conclusion or grant the investigator access to another user's evidence.
CASE_ROWS = """
SELECT c.id,c.kind,c.identity_kind,c.reported_user,c.hostname,c.product,c.accounts,c.outcome,
       c.opened_at,c.updated_at,c.closed_at,c.version,
       totals.peak::double precision AS peak,totals.session_count,totals.device_count,totals.report_count,
       COALESCE(NULLIF(latest.report->>'title',''),latest.report->'findings'->0->>'title',
                'Session investigation') AS title,
       COALESCE(latest.report->>'summary','Investigation has not produced a report yet.') AS summary
FROM risk_cases c
JOIN LATERAL (
    SELECT max(s.risk_max) AS peak,count(DISTINCT COALESCE(j.session_id,j.registration_id)) AS session_count,
           count(DISTINCT j.sensor_id) AS device_count,count(*) AS report_count
    FROM risk_case_jobs cj JOIN session_investigation_jobs j ON j.id=cj.job_id AND j.tenant_id=cj.tenant_id
    JOIN session_snapshots s ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
    WHERE cj.case_id=c.id AND cj.tenant_id=c.tenant_id
    HAVING count(*)>0
) totals ON true
LEFT JOIN LATERAL (
    SELECT a.report FROM risk_case_jobs cj
    JOIN session_investigation_jobs j ON j.id=cj.job_id AND j.tenant_id=cj.tenant_id
    JOIN session_snapshots s ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
    LEFT JOIN LATERAL (SELECT report FROM session_investigation_attempts a
        WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY ordinal DESC LIMIT 1) a ON true
    WHERE cj.case_id=c.id AND cj.tenant_id=c.tenant_id
    ORDER BY s.risk_max DESC NULLS LAST,j.created_at DESC,j.id DESC LIMIT 1
) latest ON true
WHERE c.tenant_id=$1
"""


def _offset(value):
    require(isinstance(value, str) and value.isascii() and value.isdigit(), "invalid offset")
    result = int(value)
    require(0 <= result <= 1000000, "invalid offset")
    return result


def listing(st, tenant_id, query):
    view = query.get("view", "cases")
    require(view in ("cases", "activity"), "view must be cases or activity")
    outcome, search, day = query.get("outcome", "all"), query.get("q", ""), query.get("day", "")
    require(view == "cases" or (outcome == "all" and not day), "case filters require the cases view")
    require(outcome == "all" or outcome in OUTCOMES, "invalid case outcome")
    require(len(search) <= 200, "search must be at most 200 characters")
    zone_name = query.get("time_zone", "UTC")
    try:
        zone = ZoneInfo(zone_name)
    except (ZoneInfoNotFoundError, ValueError):
        require(False, "invalid time zone")
    offsets = {kind: _offset(query.get(kind + "_offset", "0")) for kind in ("sessions", "users")}
    if day:
        try:
            require(date.fromisoformat(day).isoformat() == day, "invalid opening date")
        except ValueError:
            require(False, "invalid opening date")
    if view == "activity":
        risk_activity.request_snapshot(st, tenant_id, zone_name)
    with _read(st) as conn:
        until = st.scalar("SELECT now()", conn=conn)
        today = until.astimezone(zone).date()
        start = today - timedelta(days=29)
        since = datetime.combine(start, time.min, zone).astimezone(timezone.utc)
        settings = get_settings(st, tenant_id, conn)
        result = {"view": view, "since": since, "until": until, "time_zone": zone_name, "groups": {}, "charts": {},
                  "selection_policy": settings["selection_policy"],
                  "detection_threshold": settings["action_risk_threshold"] if settings["selection_policy"] == "risk_budget" else None}
        if view == "cases":
            for kind in ("sessions", "users"):
                # Open cases stay reachable even when opened before the chart window.
                rows = st.one(
                    f"""WITH population AS MATERIALIZED ({CASE_ROWS}
                        AND c.kind=$2 AND (c.opened_at>=$3 OR c.outcome='review') AND c.opened_at<=$4),
                    filtered AS (
                        SELECT * FROM population WHERE ($5='all' OR outcome=$5)
                        AND ($6='' OR position(lower($6) in lower(concat_ws(' ',title,summary,reported_user,hostname,array_to_string(accounts,' '))))>0)
                        AND ($7='' OR to_char(opened_at AT TIME ZONE $8,'YYYY-MM-DD')=$7)
                    ), page AS (SELECT * FROM filtered ORDER BY peak DESC NULLS LAST,opened_at DESC,id
                        LIMIT $9 OFFSET $10)
                    SELECT (SELECT count(*) FROM filtered) AS total,
                        COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY peak DESC NULLS LAST,opened_at DESC,id)
                            FROM page),'[]'::jsonb) AS items""",
                    tenant_id, kind, since, until, outcome, search, day, zone_name,
                    PAGE_SIZE, offsets[kind], conn=conn,
                )
                result["groups"][kind] = {**rows, "offset": offsets[kind], "limit": PAGE_SIZE}
        daily = st.many(
            """SELECT c.kind,to_char(c.opened_at AT TIME ZONE $4,'YYYY-MM-DD') AS day,
                count(*) FILTER(WHERE c.outcome='review') AS review,
                count(*) FILTER(WHERE c.outcome='tp') AS tp,count(*) FILTER(WHERE c.outcome='fp') AS fp
            FROM risk_cases c WHERE c.tenant_id=$1 AND c.opened_at>=$2 AND c.opened_at<=$3
                AND EXISTS (
                    SELECT 1 FROM risk_case_jobs cj
                    JOIN session_investigation_jobs j ON j.id=cj.job_id AND j.tenant_id=cj.tenant_id
                    JOIN session_snapshots s ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
                    WHERE cj.case_id=c.id AND cj.tenant_id=c.tenant_id
                )
            GROUP BY 1,2""",
            tenant_id, since, until, zone_name, conn=conn,
        )
        for kind in ("sessions", "users"):
            bins = {row["day"]: {key: value for key, value in row.items() if key != "kind"}
                    for row in daily if row["kind"] == kind}
            result["charts"][kind] = [bins.get((start + timedelta(days=n)).isoformat(), {
                "day": (start + timedelta(days=n)).isoformat(), "review": 0, "tp": 0, "fp": 0,
            }) for n in range(30)]
        if view == "activity":
            result["groups"], result["activity_snapshot"] = risk_activity.listing(
                st, tenant_id, zone_name, search, offsets, PAGE_SIZE, conn)
        return _json_safe(result)


def _reports(st, tenant_id, case_id, conn, offset=0, limit=20):
    rows = st.many(
        """SELECT j.id AS job_id,j.snapshot_id,COALESCE(j.session_id,sess.id) AS session_id,
            j.created_at,j.state,s.risk_max::double precision AS peak,a.id AS attempt_id,a.report
        FROM risk_case_jobs cj
        JOIN session_investigation_jobs j ON j.id=cj.job_id AND j.tenant_id=cj.tenant_id
        JOIN session_snapshots s ON s.id=j.snapshot_id AND s.tenant_id=j.tenant_id
        LEFT JOIN agent_sessions sess ON sess.registration_id=j.registration_id AND sess.tenant_id=j.tenant_id
        LEFT JOIN LATERAL (SELECT id,report FROM session_investigation_attempts a
            WHERE a.job_id=j.id AND a.tenant_id=j.tenant_id ORDER BY ordinal DESC LIMIT 1) a ON true
        WHERE cj.tenant_id=$1 AND cj.case_id=$2
        ORDER BY s.risk_max DESC NULLS LAST,j.created_at DESC,j.id DESC LIMIT $3 OFFSET $4""",
        tenant_id, case_id, limit, offset, conn=conn,
    )

    return [{**row, "report": investigation_report(row["report"])} for row in rows]


def _review_context(case, reports, offset):
    return _json_safe({
        "schema_version": 1, "case_id": case["id"], "case_version": case["version"],
        "scope": "displayed_page", "offset": offset, "report_count": case["report_count"],
        "reports": [{key: item[key] for key in ("job_id", "snapshot_id", "attempt_id", "state")} | {
            "report_sha256": sha256(json.dumps(item["report"], sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=False).encode()).hexdigest()
            if item["report"] is not None else None,
        } for item in reports],
    })


def _review_binding(st, tenant_id, case_id, version, supplied, conn):
    require(isinstance(supplied, dict) and type(supplied.get("schema_version")) is int
            and supplied["schema_version"] == 1 and type(supplied.get("offset")) is int
            and 0 <= supplied["offset"] <= 1000000 and isinstance(supplied.get("reports"), list)
            and 1 <= len(supplied["reports"]) <= 20
            and all(isinstance(item, dict) for item in supplied["reports"]), "invalid review context")
    offset = supplied["offset"]
    job_ids = [_uuid(item.get("job_id")) for item in supplied["reports"]]
    # Investigation writers lock the job before changing its attempt. Hold the
    # same lock while validating and recording the exact displayed report.
    st.many("""SELECT j.id FROM session_investigation_jobs j JOIN risk_case_jobs cj
            ON cj.job_id=j.id AND cj.tenant_id=j.tenant_id
            WHERE cj.tenant_id=$1 AND cj.case_id=$2 AND j.id=ANY($3::uuid[])
            ORDER BY j.id FOR UPDATE OF j""", tenant_id, case_id, job_ids, conn=conn)
    case = st.one(CASE_ROWS + " AND c.id=$2", tenant_id, case_id, conn=conn)
    reports = _reports(st, tenant_id, case_id, conn, offset)
    expected = _review_context(case, reports, offset)
    require(version == case["version"] and reports and supplied == expected,
            "Case reports changed. Refresh before saving your verdict.", 409)
    gaps = []
    if offset or len(reports) != case["report_count"]:
        gaps.append("partial_case")
    if any(item["report"] is None for item in reports):
        gaps.append("missing_report")
    if any(item["report"] is not None and (item["report"].get("gaps")
           or item["report"].get("status") == "inconclusive") for item in reports):
        gaps.append("report_gaps")
    return expected, gaps


def detail(st, tenant_id, case_id, offset="0"):
    case_id, position = _uuid(case_id), _offset(offset)
    with _read(st) as conn:
        case = st.one(CASE_ROWS + " AND c.id=$2", tenant_id, case_id, conn=conn)
        reports = _reports(st, tenant_id, case_id, conn, position)
        return _json_safe({"case": case, "reports": reports, "offset": position,
                           "review_context": _review_context(case, reports, position),
                           "has_more": position + len(reports) < case["report_count"]})


def update(st, tenant_id, case_id, data, actor):
    case_id = _uuid(case_id)
    require(set(data) in ({"outcome", "version"}, {"outcome", "version", "review_context"}),
            "provide outcome and version, with optional review context")
    require(isinstance(data["outcome"], str) and data["outcome"] in OUTCOMES, "invalid case outcome")
    require(type(data["version"]) is int and data["version"] > 0, "invalid case version")
    try:
        with st.transaction() as conn:
            row = st.one("SELECT * FROM risk_cases WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenant_id, case_id, conn=conn)
            require(row["version"] == data["version"], "Case changed. Refresh before saving your verdict.", 409)
            context, gaps = None, ["legacy_unbound"]
            if "review_context" in data:
                context, gaps = _review_binding(st, tenant_id, case_id, row["version"], data["review_context"], conn)
            if row["outcome"] != data["outcome"] or context is not None:
                st.execute(
                    """UPDATE risk_cases SET outcome=$3,closed_at=CASE WHEN $3='review' THEN NULL
                        ELSE COALESCE(closed_at,clock_timestamp()) END,version=version+1,updated_at=clock_timestamp()
                        WHERE tenant_id=$1 AND id=$2""", tenant_id, case_id, data["outcome"], conn=conn,
                )
                st.execute(
                    """INSERT INTO audit_log(id,tenant_id,actor_type,actor_id,actor_name,action,target_type,target_id,details)
                       VALUES($1,$2,'user',$3,$4,'risk-case.outcome','risk_case',$5,$6)""",
                    new_id(), tenant_id, actor["id"], actor.get("name", ""), case_id,
                    Jsonb({"before": row["outcome"], "after": data["outcome"], "version": row["version"] + 1}), conn=conn,
                )
                st.execute(
                    """INSERT INTO risk_case_review_revisions(case_id,tenant_id,revision,case_version,
                              outcome,reviewer_id,reviewer_name,review_context,completeness)
                        SELECT $1,$2,COALESCE(max(revision),0)+1,$3,$4,$5,$6,$7,$8
                        FROM risk_case_review_revisions WHERE case_id=$1 AND tenant_id=$2""",
                    case_id, tenant_id, row["version"], data["outcome"], actor["id"], actor.get("name", ""),
                    Jsonb(context) if context is not None else None, gaps, conn=conn,
                )
    except Conflict:
        require(False, "A newer open case exists for this subject. Review that case instead.", 409)
    return detail(st, tenant_id, case_id)


def download(st, tenant_id, case_id):
    """A standalone, script-free report with retained evidence and customer reports."""
    case_id = _uuid(case_id)
    with _read(st) as conn:
        case = st.one(CASE_ROWS + " AND c.id=$2", tenant_id, case_id, conn=conn)
        e = lambda value: escape(str(value))
        chunks = ['<!doctype html><html lang="en"><meta charset="utf-8">'
                  '<meta name="viewport" content="width=device-width, initial-scale=1">'
                  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
                  '<title>OpenAIDR case report</title><style>body{max-width:900px;margin:32px auto;padding:0 16px;'
                  'font:14px/1.6 system-ui;color:#1c2230}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
                  'section{border-top:1px solid #ddd;margin-top:24px}dt{font-weight:600}dd{margin:0 0 8px}'
                  '</style><h1>OpenAIDR case report</h1>',
                  f'<dl><dt>Case</dt><dd>{e(case_id)}</dd><dt>Reported identity</dt><dd>{e(case["reported_user"] or case["identity_kind"])}</dd>'
                  f'<dt>Reported agent accounts</dt><dd>{e(", ".join(case["accounts"]) or "Not reported")}</dd>'
                  f'<dt>Opened (UTC)</dt><dd>{e(case["opened_at"])}</dd><dt>Analyst outcome</dt><dd>{OUTCOMES[case["outcome"]]}</dd>'
                  f'<dt>Highest observed action risk</dt><dd>{e(case["peak"] if case["peak"] is not None else "Unavailable")}</dd></dl>',
                  '<p>Analyst outcomes are independent of model conclusions. Reports cover retained snapshots and stated gaps. '
                  'Reported identities do not verify who initiated an action. User reports collect the contributing session reports; '
                  'they are not an additional model assessment. Session and user verdicts are independent.</p>']
        size = sum(len(chunk.encode()) for chunk in chunks)
        for offset in range(0, case["report_count"], 20):
            for item in _reports(st, tenant_id, case_id, conn, offset):
                report = item["report"]
                title = (report or {}).get("title") or "Session investigation"
                chunk = (f'<section><h2>{e(title)}</h2><p>Job: {e(item["job_id"])} · Snapshot: {e(item["snapshot_id"])}'
                         f' · Attempt: {e(item["attempt_id"] or "Not recorded")} · State: {e(item["state"])}</p>'
                         f'<p>{e((report or {}).get("summary") or "No completed report is available.")}</p>'
                         f'<pre>{e(json.dumps(_json_safe(report), ensure_ascii=False, indent=2))}</pre></section>')
                size += len(chunk.encode())
                require(size <= 10 * 1024 * 1024, "Case report exceeds the 10 MiB download limit. Open its individual reports.", 413)
                chunks.append(chunk)
        return "".join(chunks) + "</html>"
