"""Tenant policy and findings for bounded URL reputation assessments."""

from openaidr_api_client.validation.web_risk import (
    THREAT_TYPES as THREAT_TYPES,
    MAX_URLS as MAX_URLS,
    MAX_URL_BYTES as MAX_URL_BYTES,
    MAX_URL_TOTAL_BYTES as MAX_URL_TOTAL_BYTES,
    MAX_RESPONSE_BYTES as MAX_RESPONSE_BYTES,
    LOOKUP_TIMEOUT as LOOKUP_TIMEOUT,
    CACHE_SIZE as CACHE_SIZE,
    URL as URL,
    PRIVATE_SUFFIXES as PRIVATE_SUFFIXES,
    _texts as _texts,
    _public_url as _public_url,
    extract_urls as extract_urls,
    _expiry as _expiry,
)


RULE_ID = "malicious-link"
RULE_NAME = "Malicious link detected"


def restriction(result):
    """Only a confirmed, unexpired match may add a restriction."""
    for match in result.get("matches", []):
        try:
            _expiry(match["expires_at"])
        except (ValueError, KeyError):
            continue
        return {"action": "deny", "reason": "The link reputation service flagged a link for phishing, malware, or unwanted software.",
                "rule": {"id": RULE_ID, "name": RULE_NAME, "source": "builtin"}}
    return None


def detection_finding(row, result):
    matches = result.get("links", {}).get("matches", [])
    if not matches:
        return None
    body = row.get("body") or {}
    return {
        "tenant_id": row["tenant_id"], "rule_id": RULE_ID, "category": "supply_chain",
        "severity": "high", "title": RULE_NAME,
        "summary": (
            f"The link reputation service flagged {len(matches)} captured URL(s) for phishing, malware, "
            "or unwanted software. This records a reputation match, not proof that a URL "
            "was opened or that an action was blocked. See the event's link assessment."
        ),
        "agent_id": row.get("agent_id"), "session_id": row.get("session_id"),
        "sensor_id": row["sensor_id"], "host": body.get("host") or {},
        "product": row.get("product") or "", "account": (body.get("agent") or {}).get("account", ""),
        "event_ids": [row["id"]], "primary_event_id": row["id"], "first_event_at": row["time"],
    }
