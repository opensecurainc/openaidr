"""Customer projections for OpenAIDR service metadata, never captured evidence."""

import hashlib
import json

from .model import public


REPRESENTATION = "customer_service_metadata_v1"
MAX_READ_REPRESENTATION = 8 << 20


def _encoded(value):
    return json.dumps(public(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _fields(value, names):
    if not isinstance(value, dict):
        return {}
    return {name: value[name] for name in names.split() if name in value}


def detection_settings(value):
    return _fields(value, """
        enabled risk_threshold investigation_percent sample_percent idle_seconds
        delivery_grace_seconds gap_wait_seconds max_runtime_seconds max_attempts
        max_concurrent hourly_attempts retry_delay_seconds history_days
        action_risk_threshold urgent_risk_threshold session_high_risk_actions
        user_high_risk_actions gap_policy selection_policy version
        detector_config_version updated_at availability
        max_credits_per_attempt hourly_credits weekly_credits
    """)


def investigation_report(value):
    if value is None:
        return None
    # These fields contain evidence and analyst narratives. Preserve their
    # complete values, including any literal provider/model names they quote.
    return _fields(value, """
        schema_version status outcome verdict title conclusion summary confidence
        reason findings finding_ids timeline evidence action_outcomes authorization
        impact recommendations alternative_explanations limitations gaps coverage
        source_coverage snapshot_id detector_config_version scope company_policies
    """)


def investigation_attempt(value):
    return _fields(value, """
        id ordinal state created_at dispatched_at completed_at target_item_count
        target_byte_count target_chunk_count
    """)


def skill_report(value):
    return None if value is None else _fields(value, """
        complete mode score scanner_version issues needs_attention intel_expires_at
        finding_text_truncated llm_cache coverage
    """)


def skill_settings(value):
    return _fields(value, """
        mode budget_blocked updated_at pilot_size key_configured worker_available
        pending running completed failed
    """)


def guardrail_assessment(value):
    if value is None:
        return None
    result = _fields(value, """
        status score category level reason confidence category_confidence assessed_at
        company_policy knowledge links hook_check_id
    """)
    if "links" in result and result["links"] is not None:
        # Retained link results have a known metadata boundary. URL matches,
        # source identifiers and reason text remain original evidence values.
        result["links"] = _fields(result["links"], "profile status checked skipped failed matches reasons checked_at")
    return result


def audit_details(action, value):
    if action == "session-detection.configure":
        return detection_settings(value)
    if action == "skill_scanning.llm.configure":
        return _fields(value, "mode")
    return value


def snapshot_item(value):
    """Project generated assessment records; captured evidence has no key filter."""
    kind, body = value.get("kind"), value.get("body")
    if kind == "event_assessment":
        safe = _fields(body, "event_id company_policy")
        safe["risk"] = guardrail_assessment(body.get("risk"))
    elif kind == "assessment":
        safe = _fields(body, """
            id tenant_id sensor_id registration_id logical_id source_revision
            target_body captured_context prepared_state status started_at completed_at
            deadline_at context_enabled context_pinned knowledge_snapshot
            context_revision scope_key scope_version company_policy assessment_generation
        """)
        safe["assessment"] = guardrail_assessment(body.get("assessment"))
    else:
        return value
    result = {**value, "body": safe}
    return {**result, "representation": REPRESENTATION,
            "retained_source_sha256": hashlib.sha256(_encoded(value)).hexdigest(),
            "representation_sha256": hashlib.sha256(_encoded(result)).hexdigest()}


def retained_read(st, tenant, row, *, conn):
    """Return a distinct view when a retained fragment contains service metadata.

    Stored response bytes, byte ranges, and hashes remain unchanged. Source
    resolution runs only after the caller's owner or analyst authorization.
    """
    response = row["response"]
    snapshot = row.get("source_snapshot_id") or response.get("version", {}).get("snapshot_id")
    if not snapshot or not response.get("items"):
        return row
    items, changed, remaining = [], False, MAX_READ_REPRESENTATION
    for fragment in response["items"]:
        rows = st.many("""SELECT i.ordinal,i.kind,i.source_id,i.body FROM session_snapshot_items i
            JOIN session_snapshots s ON s.id=i.snapshot_id
            WHERE s.tenant_id=$1 AND s.id=$2 AND i.ordinal=$3 AND i.source_id=$4""",
            tenant, snapshot, fragment["ordinal"], fragment["source_id"], conn=conn)
        if rows and rows[0]["kind"] not in ("assessment", "event_assessment"):
            items.append(fragment)
            remaining -= len(_encoded(fragment))
            continue
        changed = True
        reference = {key: fragment[key] for key in ("start", "end", "total_bytes")}
        result = _fields(fragment, "source_id ordinal")
        if rows:
            original = _encoded(rows[0])
            reference["sha256"] = hashlib.sha256(original).hexdigest()
            selected = snapshot_item(rows[0])
            safe = _encoded({key: selected[key] for key in ("ordinal", "kind", "source_id", "body")})
            if len(safe) <= remaining:
                result.update(text=safe.decode(), start=0, end=len(safe), total_bytes=len(safe),
                              sha256=hashlib.sha256(safe).hexdigest(), representation=REPRESENTATION)
                remaining -= len(safe)
        if "text" not in result:
            result.update(representation="unavailable", reason="source_metadata_unavailable")
        result["retained_source_range"] = reference
        items.append(result)
    if not changed:
        return row
    projected = {**response, "items": items, "representation": REPRESENTATION}
    return {**row, "response": projected, "representation": REPRESENTATION,
            "retained_response_sha256": row["response_sha256"],
            "response_sha256": hashlib.sha256(_encoded(projected)).hexdigest()}
