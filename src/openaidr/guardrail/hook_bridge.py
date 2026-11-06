"""Private per-launch native hook IPC. This process never makes policy decisions."""

import json
import os
from pathlib import Path
import socket
import stat
import sys


ENVIRONMENT_KEY = "OPENAIDR_MANAGED_BRIDGE"
MAX_MESSAGE = 16 * 1024 * 1024
HOOK_SECONDS = 600
HOLD_SECONDS = 570


def denied(event):
    if event == "PreToolUse":
        return {"hookSpecificOutput": {
            "hookEventName": event, "permissionDecision": "deny",
            "permissionDecisionReason": "OpenAIDR managed hold is unavailable.",
        }}
    return {"decision": "block", "reason": "OpenAIDR managed hold is unavailable.",
            "continue": False, "stopReason": "OpenAIDR managed hold is unavailable."}


def forward_if_managed(agent, event, payload, *, _owned=False):
    """Return None only outside a managed launch, including for installed hooks.

    Installed telemetry hooks have short native deadlines. The separately
    injected synchronous hook owns the decision; the bridge neutralizes only
    these OpenAIDR legacy callbacks. Other native user hooks remain untouched.
    """
    value = os.environ.get(ENVIRONMENT_KEY)
    if not value:
        return None
    try:
        path = Path(value)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("private bridge required")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError("foreign bridge")
        config = json.loads(path.read_bytes())
        if config["agent"] != agent or not isinstance(config["token"], str):
            raise ValueError("foreign bridge")
        request = json.dumps({"token": config["token"], "agent": agent,
                              "event": event, "payload": payload,
                              "owned": _owned}, allow_nan=False).encode() + b"\n"
        if len(request) > MAX_MESSAGE:
            raise ValueError("oversized hook")
        with socket.create_connection(("127.0.0.1", config["port"]), timeout=3) as connection:
            connection.settimeout(HOLD_SECONDS + 5 if _owned else 5)
            connection.sendall(request)
            stream = connection.makefile("rb")
            data = stream.readline(MAX_MESSAGE + 1)
            if not data.endswith(b"\n") or len(data) > MAX_MESSAGE:
                raise ValueError("invalid bridge reply")
            response = json.loads(data)
            if not isinstance(response, dict):
                raise ValueError("invalid bridge reply")
            return response
    except (OSError, ValueError, KeyError, TypeError):
        return denied(event)


def main():
    agent, event = sys.argv[1:3]
    try:
        raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
        payload = json.loads(raw) if len(raw) <= MAX_MESSAGE else None
        if not isinstance(payload, dict):
            raise ValueError("invalid native hook")
        result = forward_if_managed(agent, event, payload, _owned=True)
    except (ValueError, OSError):
        result = denied(event)
    sys.stdout.write(json.dumps(result if result is not None else denied(event)) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
