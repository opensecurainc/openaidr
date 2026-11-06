"""Pinned Claude stream-json adapter with hostname-preserving provider mediation."""

import asyncio
import json
import os
from pathlib import Path
import re
import uuid

from .gate import NativeOutcome
from .hook_bridge import ENVIRONMENT_KEY, HOOK_SECONDS
from .native import NativeError, NativeSession, launch_attribute
from .transport import ProviderTransport


class ClaudeAdapter(NativeSession):
    def __init__(self, options):
        super().__init__("claude", options)
        self.native_id = str(uuid.uuid4())
        self.message_offsets = {}

    def native_arguments(self):
        conflicting = {"-c", "--continue", "-r", "--resume", "--fork-session", "--from-pr",
                       "--session-id", "--input-format", "--output-format", "--permission-prompt-tool",
                       "--settings", "--setting-sources", "--bare", "--cloud", "--desktop", "--bg", "--background"}
        if any(argument.split("=", 1)[0] in conflicting for argument in self.arguments):
            raise NativeError("unsupported_native_arguments")
        return list(self.arguments)

    def routing_environment(self):
        """Read only known settings env sources; let native resolve credentials.

        Environment overrides in settings must keep their normal effect on
        provider selection and the original proxy, before our additive routing
        layer is applied. No auth token or helper is copied into settings.
        """
        result = dict(self.environment)
        config = Path(result.get("CLAUDE_CONFIG_DIR", Path(result.get("HOME", "~")) / ".claude"))
        paths = [config / "settings.json", Path(self.cwd) / ".claude/settings.json",
                 Path(self.cwd) / ".claude/settings.local.json",
                 Path("/Library/Application Support/ClaudeCode/managed-settings.json") if os.uname().sysname == "Darwin"
                 else Path("/etc/claude-code/managed-settings.json")]
        for path in paths:
            if not path.is_file():
                continue
            try:
                settings = json.loads(path.read_bytes())
                values = settings.get("env", {})
                if isinstance(values, dict):
                    for key, value in values.items():
                        if isinstance(value, str):
                            result[key] = value
                if settings.get("disableAllHooks"):
                    raise NativeError("native_hooks_unavailable")
            except (OSError, ValueError, TypeError):
                raise NativeError("native_settings_unavailable") from None
        if any(result.get(key) in ("1", "true") for key in
               ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_SIMPLE")):
            raise NativeError("unsupported_native_provider")
        return result

    async def start(self):
        try:
            await self.setup()
            args = self.native_arguments()
            self.environment = self.routing_environment()
            upstream = self.environment.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
            self.transport = ProviderTransport(self, upstream, connect=True)
            routing = self.transport.child_environment()
            routing[ENVIRONMENT_KEY] = str(self.bridge_path)
            if launch_id := self.child_environment.get("OPENAIDR_MANAGED_LAUNCH_ID"):
                self.environment["OPENAIDR_MANAGED_LAUNCH_ID"] = launch_id
                routing["OPENAIDR_MANAGED_LAUNCH_ID"] = launch_id
            if attributes := launch_attribute(self.environment):
                routing["OTEL_RESOURCE_ATTRIBUTES"] = attributes
            self.child_environment.update(routing)
            # A final additional settings layer makes the transport effective
            # even when user settings contain a proxy variable. Every other
            # saved setting and all existing hook groups remain native-owned.
            self.settings_path = self.directory / "claude-managed-settings.json"
            settings = {"env": routing, "hooks": {
                event: [{"hooks": [{"type": "command", "command": self.hook_command(event),
                                    "timeout": HOOK_SECONDS}]}]
                for event in ("PreToolUse", "PostToolUse")}}
            with open(self.settings_path, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                json.dump(settings, stream)
            await self.spawn([self.binary, *args, "-p", "--verbose", "--input-format", "stream-json",
                              "--output-format", "stream-json", "--permission-prompt-tool", "stdio",
                              "--session-id", self.native_id, "--settings", str(self.settings_path)])
            await self.control({"subtype": "initialize"})
            self.started.set()
            return self.info()
        except BaseException:
            await self.close()
            raise

    async def control(self, request):
        ident = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        try:
            await self.send({"type": "control_request", "request_id": ident, "request": request})
            return await asyncio.wait_for(future, 30)
        finally:
            self.pending.pop(ident, None)

    async def message(self, message):
        kind = message.get("type")
        if kind == "control_response":
            response = message.get("response", {})
            future = self.pending.get(response.get("request_id"))
            if future and not future.done():
                if response.get("subtype") == "success":
                    future.set_result(response.get("response", {}))
                else:
                    future.set_exception(NativeError("native_rpc_rejected"))
        elif kind == "control_request":
            self.task(self.permission(message), callback=True)
        elif kind == "assistant":
            value = message.get("message", {})
            ident = value.get("id") or message.get("uuid")
            offset = self.message_offsets.get(ident, 0)
            content = value.get("content", [])
            self.message_offsets[ident] = offset + len(content)
            for index, block in enumerate(content, offset):
                if block.get("type") == "text":
                    self.queue_display(self.assistant_text, str(ident) + ":" + str(index), block.get("text", ""))
        elif kind == "result":
            self.task(self.finish_turn("failed" if message.get("is_error") else "completed"))
        elif kind == "user":
            content = message.get("message", {}).get("content", [])
            if isinstance(content, list):
                for item in content:
                    if item.get("type") != "tool_result":
                        continue
                    call = self.calls.get(item.get("tool_use_id"))
                    if call and not call["completion"].done():
                        failed = bool(item.get("is_error"))
                        # This pin reports Bash failure code in its native
                        # result framing, not a structured SDK integer field.
                        text = item.get("content")
                        match = re.match(r"Exit code (-?\d+)\n", text) if failed and call["name"] == "Bash" and isinstance(text, str) else None
                        code = int(match[1]) if match and -(1 << 31) <= int(match[1]) < 1 << 31 else None
                        call["completion"].set_result(NativeOutcome("failed" if failed else "succeeded", code))

    async def permission(self, message):
        ident, request = message["request_id"], message.get("request", {})
        cancel = {"behavior": "deny", "message": "Native permission was not granted."}
        if request.get("subtype") != "can_use_tool":
            await self.send({"type": "control_response", "response": {
                "subtype": "error", "request_id": ident, "error": "Managed host request is unsupported"}})
            return
        original = request.get("input", {})
        allow = {"behavior": "allow", "updatedInput": original}
        values = [cancel, allow]
        dto = {"id": ident, "method": "can_use_tool", "tool": request.get("tool_name"),
               "input": original, "cwd": self.cwd,
               "choices": [{"label": "Deny", "value": cancel}, {"label": "Allow once", "value": allow}],
               "cancel": cancel}
        answer = await self.approval_choice(dto)
        if answer not in values:
            answer = cancel
        await self.send({"type": "control_response", "response": {
            "subtype": "success", "request_id": ident, "response": answer}})

    async def submit(self, prompt):
        if not self.attached.is_set() or self.closed:
            raise NativeError("native_not_attached")
        async with self.turn_lock:
            self.turn_status = "completed"
            self.turn_id = str(uuid.uuid4())
            self.turn_done = asyncio.get_running_loop().create_future()
            held = self.action("prompt:" + self.turn_id, "prompt", prompt)
            async def release(_):
                await self.send({"type": "user", "message": {"role": "user", "content": prompt},
                                 "session_id": self.native_id})
                return NativeOutcome("succeeded")
            result = await self.gate.gate(held, release)
            if result.status != "succeeded":
                await self.retire_turn()
                return {"turn_id": self.turn_id, "status": "blocked" if result.status == "blocked" else "uncertain"}
            status = await self.turn_done
            await self.retire_turn()
            return {"turn_id": self.turn_id, "status": status}

    async def cancel(self):
        for task in tuple(self.callback_tasks):
            if task is not asyncio.current_task():
                task.cancel()
        if self.process and self.process.returncode is None and self.turn_id:
            try:
                await asyncio.wait_for(self.control({"subtype": "interrupt"}), 3)
            except (Exception, asyncio.CancelledError):
                pass
        if self.turn_done and not self.turn_done.done():
            self.turn_done.set_result("cancelled" if self.turn_status == "completed" else self.turn_status)
