"""Device-scoped ordinary hook summaries and denial reviews."""

from datetime import datetime, timedelta, timezone
import hashlib
import json

from psycopg.types.json import Jsonb

from .customer_views import REPRESENTATION, guardrail_assessment
from .hook_policy import get_settings
from .httpx import APIError, require, uuid_param
from .store import Cursor, decode_cursor


def overview(st, sensor, days):
    with st.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        conn.execute("SET LOCAL statement_timeout='5s'")
        until = conn.execute("SELECT now() AS time").fetchone()["time"].astimezone(timezone.utc)
        since = until - timedelta(days=days)
        mode = get_settings(st, sensor["tenant_id"], conn)["mode"]
        scope = (sensor["tenant_id"], sensor["id"], since, until)
        # Expired work is unavailable, matching the ordinary hook decision list.
        # Neither a policy decision nor a returned response proves enforcement.
        status = "CASE WHEN status='pending' AND deadline_at<=%s THEN 'unavailable' ELSE status END"
        rows = conn.execute(
            f"""SELECT product,mode,{status} AS state,evaluated_decision,count(*) AS count,
                       max(created_at) AS last_check_at
                FROM ordinary_hook_checks
                WHERE tenant_id=%s AND sensor_id=%s AND created_at>=%s AND created_at<%s
                GROUP BY product,mode,state,evaluated_decision""",
            (until, *scope),
        ).fetchall()
        recent = conn.execute(
            f"""SELECT id,created_at,product,hook_event,mode,{status} AS status,
                       evaluated_decision,returned_decision
                FROM ordinary_hook_checks
                WHERE tenant_id=%s AND sensor_id=%s AND created_at>=%s AND created_at<%s
                ORDER BY created_at DESC,id DESC LIMIT 20""",
            (until, *scope),
        ).fetchall()

    def counts():
        return dict(completed=0, allow=0, warn=0, ask=0, deny=0, unavailable=0, pending=0)

    summary = counts()
    by_mode = {name: counts() for name in ("shadow", "enforce")}
    last_checks = {}
    for row in rows:
        key = row["evaluated_decision"] if row["state"] == "evaluated" else row["state"]
        for target in (summary, by_mode[row["mode"]]):
            target[key] += row["count"]
            if row["state"] == "evaluated":
                target["completed"] += row["count"]
        product = row["product"]
        last_checks[product] = max(last_checks.get(product, since), row["last_check_at"])
    return dict(
        days=days, since=since.isoformat(), until=until.isoformat(), mode=mode,
        summary=summary, by_mode=by_mode,
        by_agent=[dict(product=product, last_check_at=stamp.isoformat())
                  for product, stamp in sorted(last_checks.items())],
        recent=[{**row, "created_at": row["created_at"].isoformat()} for row in recent],
    )


def review_evidence(row):
    settings = row["risk_settings"]
    captured = row["assessment_input"]
    manifest = row["assessment_context"]
    gaps = ["bounded_context", "service_request_mapping_unavailable"]
    if captured is None:
        gaps.append("assessment_input_not_retained")
    if "policy_snapshot" not in settings:
        gaps.append("policy_snapshot_not_retained")
    if settings.get("retained_evidence_id"):
        gaps.append("retained_evidence_not_in_snapshot")
    availability = settings.get("availability", "unknown")
    if availability != "available":
        gaps.append(availability)
    if settings.get("content_redacted") or (manifest or {}).get("content_redacted"):
        gaps.append("content_redacted")
    if (manifest or {}).get("context_truncated"):
        gaps.append("context_truncated")
    if (manifest or {}).get("content_truncated"):
        gaps.append("content_truncated")
    if "content_redacted" not in settings or (manifest or {}).get("redaction_status_unknown"):
        gaps.append("redaction_status_unknown")
    evidence = {
        "schema_version": 1, "representation": REPRESENTATION, "subject_type": "hook_check", "subject_id": str(row["id"]),
        "actions": row["actions"], "assessment_input": captured,
        "assessment_input_sha256": row["assessment_input_sha256"], "context_manifest": manifest,
        "decision_basis": {
            "mode": row["mode"], "settings_version": row["settings_version"],
            "policy_version": row["policy_version"], "policy": settings.get("policy_snapshot"),
            "company_policy": settings.get("company_policy"),
            "control_supported": settings.get("control_supported"),
            "risk_settings": {key: settings[key] for key in ("enabled", "ask_threshold", "block_threshold") if key in settings},
            "rule_decision": settings.get("rule_decision"), "matched_rule": row["matched_rule"],
        },
        "assessment": guardrail_assessment(row["assessment"]),
        "decision": {key: row[key] for key in ("evaluated_decision", "returned_decision", "reason", "failure_reason")},
        "service_request_ids": [], "gaps": sorted(set(gaps)),
    }
    encoded = json.dumps(evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return evidence, hashlib.sha256(encoded).hexdigest()


def review_request(st, sensor, action, data):
    data = dict(data)
    version = data.pop("review_version", 0)
    require(type(version) is int and version in (0, 1), "unsupported review version")
    decision = data.pop("decision", "deny") if action in ("denials", "check") else "deny"
    require(decision in ("ask", "deny"), "unsupported check decision")
    fields = """c.id,c.created_at,c.product,c.hook_event,c.mode,c.returned_decision,
                r.label,r.note,r.updated_at AS reviewed_at"""
    if version:
        fields += ",COALESCE(r.revision,0) AS review_revision"
    else:
        fields = fields.replace("r.label,r.note,r.updated_at", """CASE WHEN r.label='insufficient_context' THEN NULL ELSE r.label END AS label,
            CASE WHEN r.label='insufficient_context' THEN NULL ELSE r.note END AS note,
            CASE WHEN r.label='insufficient_context' THEN NULL ELSE r.updated_at END""")
    scope = "c.tenant_id=%s AND c.sensor_id=%s AND c.status='evaluated' AND c.evaluated_decision=%s"
    identity = (sensor["tenant_id"], sensor["id"], decision)
    with st.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout='5s'")
        if action == "denials":
            require(set(data) == {"days", "until", "cursor"}, "invalid denial list parameters")
            require(type(data["days"]) is int and data["days"] in (1, 30), "days must be 1 or 30")
            require(isinstance(data["until"], str) and isinstance(data["cursor"], str)
                    and len(data["cursor"]) <= 256, "invalid denial window")
            try:
                until = datetime.fromisoformat(data["until"].replace("Z", "+00:00"))
                require(until.tzinfo is not None, "invalid denial window")
                since = until - timedelta(days=data["days"])
                cursor = decode_cursor(data["cursor"])
            except (ValueError, OverflowError):
                raise APIError(400, "invalid denial window or cursor") from None
            rows = conn.execute(
                f"""SELECT {fields} FROM ordinary_hook_checks c
                    LEFT JOIN ordinary_hook_reviews r ON r.check_id=c.id
                    WHERE {scope} AND c.created_at>=%s AND c.created_at<%s
                    AND (%s::timestamptz IS NULL OR (c.created_at,c.id)<(%s,%s::uuid))
                    ORDER BY c.created_at DESC,c.id DESC LIMIT 21""",
                (*identity, since, until, cursor.time, cursor.time, cursor.id or None),
            ).fetchall()
            last = rows[19] if len(rows) > 20 else None
            return {"items": rows[:20], "next_cursor": Cursor(last["created_at"], str(last["id"])).encode() if last else "",
                    "review_version": 1}
        required = {"id"} if action == "check" else {"id", "label", "note"}
        if version and action == "review":
            required |= {"evidence_sha256", "expected_revision", "request_id"}
        require(set(data) == required, "invalid review parameters")
        ident = uuid_param(data["id"], "check id")
        if action == "check":
            extra = ",c.*" if version else ",c.actions,c.reason"
            row = conn.execute(
                f"""SELECT {fields}{extra} FROM ordinary_hook_checks c
                    LEFT JOIN ordinary_hook_reviews r ON r.check_id=c.id WHERE {scope} AND c.id=%s""",
                (*identity, ident),
            ).fetchone()
            require(row is not None, "denied check not found", 404)
            if version:
                evidence, digest = review_evidence(row)
                return {**{key: row[key] for key in ("id", "created_at", "product", "hook_event", "mode", "returned_decision",
                                                    "label", "note", "reviewed_at", "review_revision", "actions", "reason")},
                        "review_version": 1, "evidence": evidence, "evidence_sha256": digest}
            return dict(row)
        labels = ("correct_denial", "false_positive", "insufficient_context") if version else ("correct_denial", "false_positive")
        require(data["label"] in labels, "invalid review label")
        require(isinstance(data["note"], str) and len(data["note"]) <= 2000 and "\x00" not in data["note"], "invalid review note")
        row = conn.execute(
            f"SELECT c.* FROM ordinary_hook_checks c WHERE {scope} AND c.id=%s FOR UPDATE", (*identity, ident),
        ).fetchone()
        require(row is not None, "denied check not found", 404)
        current = conn.execute("SELECT revision FROM ordinary_hook_reviews WHERE check_id=%s", (ident,)).fetchone()
        revision = current["revision"] if current else 0
        request_id, digest = None, None
        if version:
            request_id = uuid_param(data["request_id"], "review request id")
            require(type(data["expected_revision"]) is int and data["expected_revision"] >= 0, "invalid review revision")
            require(isinstance(data["evidence_sha256"], str) and len(data["evidence_sha256"]) == 64, "invalid evidence hash")
            previous = conn.execute(
                "SELECT * FROM ordinary_hook_review_revisions WHERE check_id=%s AND request_id=%s", (ident, request_id),
            ).fetchone()
            if previous:
                require(previous["label"] == data["label"] and previous["note"] == data["note"]
                        and previous["evidence_sha256"] == data["evidence_sha256"]
                        and previous["revision"] == data["expected_revision"] + 1, "review request changed", 409)
                return {"id": ident, "label": previous["label"], "note": previous["note"],
                        "reviewed_at": previous["reviewed_at"], "review_revision": previous["revision"], "review_version": 1}
            require(revision == data["expected_revision"], "review changed; reopen the check", 409)
            evidence, digest = review_evidence(row)
            require(digest == data["evidence_sha256"], "review evidence changed; reopen the check", 409)
            conn.execute(
                """INSERT INTO ordinary_hook_review_evidence(check_id,sha256,evidence) VALUES(%s,%s,%s)
                   ON CONFLICT(check_id,sha256) DO NOTHING""", (ident, digest, Jsonb(evidence)),
            )
        revision += 1
        saved = conn.execute(
            """INSERT INTO ordinary_hook_review_revisions(check_id,revision,label,note,source_id,request_id,evidence_sha256)
               VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING reviewed_at""",
            (ident, revision, data["label"], data["note"], sensor["id"], request_id, digest),
        ).fetchone()
        conn.execute(
            """INSERT INTO ordinary_hook_reviews(check_id,label,note,updated_at,revision) VALUES(%s,%s,%s,%s,%s)
               ON CONFLICT(check_id) DO UPDATE SET label=EXCLUDED.label,note=EXCLUDED.note,
                   updated_at=EXCLUDED.updated_at,revision=EXCLUDED.revision""",
            (ident, data["label"], data["note"], saved["reviewed_at"], revision),
        )
        return {"id": ident, "label": data["label"], "note": data["note"], **dict(saved),
                **({"review_version": 1, "review_revision": revision} if version else {})}
