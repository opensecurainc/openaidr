"""Native response formatting for ordinary coding-agent hooks."""

from openaidr.core.hook_protocol import APP_PRODUCTS, controls

# When several actions of one call match, the strictest rule decides it.
PRECEDENCE = {"deny": 0, "ask": 1, "warn": 2, "allow": 3}


def native_response(product, event, action, reason, payload):
    """Translate a validated backend restriction into a native hook response."""
    if action == "allow":
        return action, {}
    if product in APP_PRODUCTS:
        if not controls(product, event):
            raise ValueError("unsupported hook boundary")
        # These boundaries have no portable warning-only response. Record the
        # backend warning, but never claim a native warning was delivered.
        if action == "warn":
            return "allow", {}
        if action not in ("deny", "ask"):
            raise ValueError("unsupported hook decision")
        if product == "github-copilot":
            return action, {"permissionDecision": action, "permissionDecisionReason": reason}
        if product == "antigravity":
            return action, {"decision": "force_ask" if action == "ask" else "deny", "reason": reason}
        if product == "hermes-agent":
            return action, {"action": "approve" if action == "ask" else "block", "message": reason}
        if product == "workbuddy":
            return action, {"hookSpecificOutput": {
                "hookEventName": event, "permissionDecision": action, "permissionDecisionReason": reason,
            }}
        if product == "cursor":
            return "deny", ({"permission": "deny", "user_message": reason, "agent_message": reason}
                            if event == "PreToolUse" else {"continue": False, "user_message": reason})
        # OpenCode's plugin bridge throws only this validated backend denial.
        return "deny", {"decision": "deny", "reason": reason}
    if action == "warn":
        return action, {"systemMessage": "OpenAIDR warning: " + reason}
    if action not in ("deny", "ask"):
        raise ValueError("unsupported hook decision")
    if event == "PreToolUse":
        enforced = "deny" if product == "codex-cli" else action
        return enforced, {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": enforced,
                "permissionDecisionReason": reason,
            }
        }
    if event == "UserPromptSubmit" or (
        event == "PostToolUse" and product == "codex-cli"
    ):
        return "deny", {"decision": "block", "reason": reason}
    if event == "PostToolUse" and product == "claude-code":
        tool, value = payload.get("tool_name", ""), payload.get("tool_response")
        if tool == "Bash" and isinstance(value, dict) and all(
            isinstance(value.get(key), expected)
            for key, expected in (
                ("stdout", str), ("stderr", str), ("interrupted", bool), ("isImage", bool)
            )
        ):
            replacement = {"stdout": reason, "stderr": "", "interrupted": False, "isImage": False}
        else:
            raise ValueError("unsupported tool result schema")
        return "deny", {
            "hookSpecificOutput": {"hookEventName": event, "updatedToolOutput": replacement}
        }
    raise ValueError("unsupported hook boundary")
