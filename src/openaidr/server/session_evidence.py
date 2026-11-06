"""Bounded, tenant-scoped reads of captured session observations."""

import base64
import json
import re
import uuid
from datetime import datetime, timezone

from openaidr.core.event import validate_evidence
from . import _sql as sql


MAX_SEQUENCE = (1 << 63) - 1
ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,128}$"


def decode_cursor(value):
    if not value:
        return "", -1, -1, datetime.min.replace(tzinfo=timezone.utc), str(uuid.UUID(int=0))
    try:
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
        parts = json.loads(raw)
        if not isinstance(parts, list) or len(parts) != 5:
            raise ValueError
        stream, sequence, part, time, event_id = parts
        if not isinstance(stream, str) or len(stream) > 128:
            raise ValueError
        if any(type(n) is not int or not -1 <= n <= MAX_SEQUENCE for n in (sequence, part)):
            raise ValueError
        if stream and (not re.fullmatch(ID_PATTERN, stream) or sequence < 0 or part < 0):
            raise ValueError
        if not stream and (sequence != -1 or part != -1):
            raise ValueError
        time = datetime.fromisoformat(time.replace("Z", "+00:00"))
        if time.tzinfo is None:
            raise ValueError
        event_id = str(uuid.UUID(event_id))
        return stream, sequence, part, time, event_id
    except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise ValueError("invalid cursor") from exc


def _encode_cursor(row):
    parts = [
        row["evidence_stream"], row["evidence_sequence"], row["evidence_part"],
        row["time"].isoformat(), row["id"],
    ]
    return base64.urlsafe_b64encode(json.dumps(parts).encode()).decode().rstrip("=")


def read_page(st, tenant_id, session_id, limit=50, cursor="", *, owner_user_id=None):
    if owner_user_id is None:
        st.get_session_row(tenant_id, session_id)
    else:
        st.one(
            """SELECT s.id FROM agent_sessions s
               JOIN session_registrations r ON r.id=s.registration_id
               JOIN tenant_users u ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id
               WHERE s.tenant_id=$1 AND s.id=$2 AND r.tenant_id=$1
                 AND r.owner_user_id=$3 AND r.verified_at IS NOT NULL AND u.status='active'""",
            tenant_id, session_id, owner_user_id,
        )
    position = decode_cursor(cursor)
    limit = min(limit, 500) if limit > 0 else 50
    order = 'evidence_stream COLLATE "C",evidence_sequence,evidence_part,time,id'
    rows = st.many(
        f"""SELECT {sql.eventColumns},evidence_stream,evidence_sequence,evidence_part
          FROM events WHERE tenant_id=$1 AND session_id=$2
          AND ($9::uuid IS NULL OR EXISTS (
              SELECT 1 FROM agent_sessions owned
              JOIN session_registrations r ON r.id=owned.registration_id
              JOIN tenant_users u ON u.id=r.owner_user_id AND u.tenant_id=r.tenant_id
              WHERE owned.id=events.session_id AND owned.tenant_id=$1
                AND r.tenant_id=$1 AND r.owner_user_id=$9
                AND r.verified_at IS NOT NULL AND u.status='active'
          ))
          AND ({order})>($3 COLLATE "C",$4::bigint,$5::bigint,$6::timestamptz,$7::uuid)
          ORDER BY {order} LIMIT $8""",
        tenant_id, session_id, *position, limit + 1, owner_user_id,
    )
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = _encode_cursor(rows[-1]) if more else ""
    legacy = unknown = 0
    gaps = set()
    for row in rows:
        for key in ("evidence_stream", "evidence_sequence", "evidence_part"):
            row.pop(key)
        body = row["body"]
        metadata = body.get("evidence")
        if "evidence" not in body:
            status = "legacy"
            legacy += 1
        elif validate_evidence(metadata):
            status = "unknown"
            unknown += 1
        else:
            status = "reported"
        known = status == "reported"
        tool = body.get("tool")
        call_id = tool.get("call_id") if isinstance(tool, dict) else None
        row["evidence"] = {
            "status": status,
            **{
                key: metadata[key] if known else None
                for key in ("logical_id", "observation_id", "stream_id", "sequence", "part")
            },
            "tool_call_id": call_id if isinstance(call_id, str) else None,
            "gaps": metadata["gaps"] if known else [],
        }
        gaps.update(row["evidence"]["gaps"])
    return {
        "items": rows,
        "next_cursor": next_cursor,
        "coverage": {
            "scope": "page",
            "status": "incomplete" if gaps else "unknown",
            "delivery": "unknown",
            "cross_stream_order": "unknown",
            "observations": len(rows),
            "legacy_observations": legacy,
            "unknown_observations": unknown,
            "gaps": sorted(gaps),
        },
    }
