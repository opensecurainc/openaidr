"""Product identities and native payloads for ordinary local agent hooks."""

import json

PRODUCTS = {
    "claude": "claude-code", "codex": "codex-cli", "copilot": "github-copilot",
    "cursor": "cursor", "antigravity": "antigravity", "opencode": "opencode", "hermes": "hermes-agent",
    "workbuddy": "workbuddy",
}
ROUTES = {product: "/v1/hooks/" + ("codex" if agent == "codex" else product)
          for agent, product in PRODUCTS.items()}

# Canonical event -> native configuration key. Do not register both generic
# and tool-specific hooks: that would evaluate the same call twice.
APP_EVENTS = {
    "workbuddy": {event: event for event in (
        "PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit", "SessionStart", "SessionEnd", "Stop",
    )},
    "copilot": {
        "PreToolUse": "preToolUse", "PostToolUse": "postToolUse",
        "PostToolUseFailure": "postToolUseFailure", "UserPromptSubmit": "userPromptSubmitted",
        "SessionStart": "sessionStart", "SessionEnd": "sessionEnd", "Stop": "agentStop",
    },
    "cursor": {
        "PreToolUse": "preToolUse", "PostToolUse": "postToolUse",
        "PostToolUseFailure": "postToolUseFailure", "UserPromptSubmit": "beforeSubmitPrompt",
        "SessionStart": "sessionStart", "SessionEnd": "sessionEnd", "Stop": "afterAgentResponse",
    },
    "antigravity": {event: event for event in ("PreToolUse", "PostToolUse", "SessionStart", "Stop")},
    "opencode": {
        "PreToolUse": "tool.execute.before", "PostToolUse": "tool.execute.after",
        "UserPromptSubmit": "chat.message", "SessionStart": "session.created",
    },
    "hermes": {
        "PreToolUse": "pre_tool_call", "PostToolUse": "post_tool_call",
        "UserPromptSubmit": "pre_llm_call", "Stop": "post_llm_call",
        "SessionStart": "on_session_start", "SessionEnd": "on_session_finalize",
    },
}
APP_PRODUCTS = frozenset(PRODUCTS[agent] for agent in APP_EVENTS)


def controls(product, event):
    """Result replacement for existing agents also needs executable evidence."""
    if product not in APP_PRODUCTS:
        return True
    return event == "PreToolUse" or (product == "cursor" and event == "UserPromptSubmit")


def normalize(product, payload):
    """Copy native identity and evidence fields without interpreting tool text."""
    p = dict(payload)
    agent = next((key for key, value in PRODUCTS.items() if value == product), None)
    aliases = {value: key for key, value in APP_EVENTS.get(agent, {}).items()}
    event = p.get("hook_event_name")
    p["hook_event_name"] = aliases.get(event, event)
    if product == "github-copilot":
        for native, canonical in (
            ("sessionId", "session_id"), ("toolName", "tool_name"), ("toolArgs", "tool_input"),
            ("transcriptPath", "transcript_path"),
        ):
            if native in p:
                p[canonical] = p[native]
        if isinstance(p.get("tool_input"), str):
            try:
                p["tool_input"] = json.loads(p["tool_input"])
            except ValueError:
                pass
        result = p.get("toolResult", p.get("tool_result"))
        if isinstance(result, dict):
            p["tool_response"] = result.get("textResultForLlm", result.get("text_result_for_llm", result))
    elif product == "cursor":
        p["session_id"] = p.get("conversation_id", "")
        roots = p.get("workspace_roots")
        if not p.get("cwd") and isinstance(roots, list) and len(roots) == 1 and isinstance(roots[0], str):
            p["cwd"] = roots[0]
        if "tool_output" in p:
            p["tool_response"] = p["tool_output"]
        if "error_message" in p:
            p["error"] = p["error_message"]
        if p["hook_event_name"] == "Stop":
            p["last_assistant_message"] = p.get("text", "")
    elif product == "antigravity":
        p["session_id"] = p.get("conversationId", "")
        p["model"] = p.get("modelName", "")
        p["transcript_path"] = p.get("transcriptPath", "")
        roots = p.get("workspacePaths")
        if isinstance(roots, list) and len(roots) == 1 and isinstance(roots[0], str):
            p["cwd"] = roots[0]
        call = p.get("toolCall")
        if isinstance(call, dict):
            p["tool_name"], p["tool_input"] = call.get("name"), call.get("args")
        if type(p.get("stepIdx")) is int and p["stepIdx"] >= 0:
            p["tool_use_id"] = str(p["stepIdx"])
        if p["hook_event_name"] == "PostToolUse" and p.get("error"):
            p["hook_event_name"] = "PostToolUseFailure"
    elif product == "hermes-agent":
        extra = p.get("extra")
        if isinstance(extra, dict):
            for native, canonical in (
                ("tool_call_id", "tool_use_id"), ("model", "model"),
                ("result", "tool_response"), ("user_message", "prompt"),
                ("assistant_response", "last_assistant_message"), ("error_message", "error"),
            ):
                if native in extra:
                    p[canonical] = extra[native]
            if p["hook_event_name"] == "PostToolUse" and extra.get("status") in ("error", "timeout"):
                p["hook_event_name"] = "PostToolUseFailure"
                p["error"] = extra.get("error_message") or extra.get("result", "")
    return p
