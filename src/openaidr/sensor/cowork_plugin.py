"""Build a personal Cowork plugin. No installed Claude settings are modified."""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import ZipFile

from openaidr import build_info


def build(connection_file, output):
    config = json.loads(Path(connection_file).read_text(encoding="utf-8"))
    if config.get("kind") != "plugin" or not isinstance(config.get("token"), str) or not config["token"].startswith("oacw_"):
        raise ValueError("A personal plugin connection with its issued token is required")
    url = urlsplit(config.get("hook_url", ""))
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or not url.path.endswith("/hooks")):
        raise ValueError("The plugin requires a public HTTPS hook URL")
    root = Path(__file__).resolve().parents[3]
    version = (build_info.resolve(root) if (root / ".git").exists() else build_info.current())["version"]
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Contains a revocable, connection-scoped credential, never a sensor token.
    with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        with ZipFile(stream, "w") as archive:
            archive.writestr(".claude-plugin/plugin.json", json.dumps({
                "name": "openaidr-cowork", "version": version,
                "description": "OpenAIDR policy checks for Cowork prompts and tools",
            }))
            command = 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/client.py" 2>/dev/null || true'
            archive.writestr("hooks/hooks.json", json.dumps({"hooks": {
                event: [{"matcher": "", "hooks": [{"type": "command", "command": command, "timeout": 3}]}]
                for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure")
            }}))
            archive.writestr("hooks/connection.json", json.dumps({
                "hook_url": config["hook_url"], "token": config["token"],
                "capture_content": config.get("capture_content", False),
            }))
            archive.write(Path(__file__).with_name("cowork_plugin_client.py"), "hooks/client.py")
    return target.resolve()
