"""Tenant findings from validated Guardrail outcomes and captured evidence."""

DETECTION_RULE_ID = "jev-risk-detection"
# Material assessments raise detections for these agent-activity kinds: the
# live-activity prompt, tool call, and tool result groups. A tool call covers
# the command, file, and network kinds the sensor maps tool use to.
ACTIVITY_LABELS = {
    "prompt": "prompt",
    "tool.call": "tool call",
    "tool.result": "tool result",
    "command": "tool call",
    "file.read": "tool call",
    "file.write": "tool call",
    "network": "tool call",
}
DETECTION_LEVELS = ("medium", "high", "critical")
CATEGORY_LABELS = {
    "secret_exfiltration": "Secret exfiltration",
    "data_exfiltration": "Data exfiltration",
    "supply_chain": "Supply chain",
    "destructive_command": "Destructive command",
    "excessive_agency": "Excessive agency",
    "hallucination": "Hallucination",
}


def detection_finding(row, result):
    """Build the detection for a material assessment of agent activity.

    Returns None when the event kind or assessment stays advisory. The store
    calls this in the transaction that writes the terminal assessment, so a
    stored detection always has its assessment and its evidence event.
    """
    activity = ACTIVITY_LABELS.get(row.get("kind", ""))
    if activity is None:
        return None
    if result.get("status") != "scored" or result.get("level") not in DETECTION_LEVELS:
        return None
    category, level = result["category"], result["level"]
    label = CATEGORY_LABELS.get(category, category)
    body = row.get("body")
    body = body if isinstance(body, dict) else {}
    agent = body.get("agent")
    return {
        "tenant_id": row["tenant_id"],
        "rule_id": DETECTION_RULE_ID,
        "category": category,
        "severity": level,
        "title": f"{label} risk in a {activity}",
        "summary": (
            f"Guardrail assessed this {activity} as {label.lower()} at "
            f"{level} severity ({result['score']:g}/100, severity confidence "
            f"{result['confidence']:g}, category confidence "
            f"{result['category_confidence']:g})."
        ),
        "agent_id": row.get("agent_id"),
        "session_id": row.get("session_id"),
        "sensor_id": row["sensor_id"],
        "host": body.get("host") or {},
        "product": row.get("product") or "",
        "account": (agent.get("account") or "") if isinstance(agent, dict) else "",
        "event_ids": [row["id"]],
        "primary_event_id": row["id"],
        "first_event_at": row["time"],
    }
