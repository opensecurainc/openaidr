"""Pinned Codex app-server adapter, retaining native tools and permissions."""

import asyncio
import hashlib
import json
import re
import uuid
from urllib.parse import urlsplit

from .gate import NativeOutcome
from .hook_bridge import HOOK_SECONDS
from .journal import canonical
from .native import NativeError, NativeSession
from .transport import ProviderTransport


class CodexAdapter(NativeSession):
    def __init__(self, options):
        super().__init__("codex", options)
        self.thread_options = {}

    def native_arguments(self):
        args, iterator = [], iter(self.arguments)
        mappings = {"-m": "model", "--model": "model", "-s": "sandbox", "--sandbox": "sandbox",
                    "-a": "approvalPolicy", "--ask-for-approval": "approvalPolicy"}
        for value in iterator:
            if value in ("-c", "--config", "--enable", "--disable"):
                try:
                    argument = next(iterator)
                except StopIteration:
                    raise NativeError("invalid_native_arguments") from None
                if value in ("-c", "--config") and argument.split("=", 1)[0].startswith("hooks"):
                    raise NativeError("unsupported_native_hook_override")
                args.extend((value, argument))
            elif value in mappings:
                try:
                    self.thread_options[mappings[value]] = next(iterator)
                except StopIteration:
                    raise NativeError("invalid_native_arguments") from None
            elif value == "--search":
                args.extend(("-c", 'web_search="live"'))
            else:
                raise NativeError("unsupported_native_arguments")
        return args

    def hook_arguments(self):
        args, states = [], {}
        for event, label in (("PreToolUse", "pre_tool_use"), ("PostToolUse", "post_tool_use")):
            command = self.hook_command(event)
            hook = {"type": "command", "command": command, "timeout": HOOK_SECONDS, "async": False}
            identity = {"event_name": label, "hooks": [hook]}
            digest = "sha256:" + hashlib.sha256(canonical(identity)).hexdigest()
            key = f"/<session-flags>/config.toml:{label}:0:0"
            states[key] = digest
            args += ["-c", f"hooks.{event}=[{{hooks=[{{type=\"command\",command={json.dumps(command)},timeout={HOOK_SECONDS}}}]}}]"]
        state = ",".join(f"{json.dumps(key)}={{trusted_hash={json.dumps(value)}}}" for key, value in states.items())
        args += ["-c", "hooks.state={" + state + "}"]
        return args

    async def start(self):
        try:
            await self.setup()
            args = self.native_arguments()
            command = [self.binary, "app-server", "--stdio", *args, *self.hook_arguments()]
            await self.initialize(command)
            config = (await self.rpc("config/read", {"cwd": self.cwd, "includeLayers": False}))["config"]
            provider = config.get("model_provider") or "openai"
            definition = config.get("model_providers", {}).get(provider, {})
            if not re.fullmatch(r"[A-Za-z0-9_-]+", provider) or definition.get("wire_api", "responses") != "responses" or definition.get("aws") or provider in ("amazon-bedrock", "amazon-bedrock-runtime", "ollama", "lmstudio"):
                raise NativeError("unsupported_native_provider")
            # The pin ignores model_providers.openai overrides. Its built-in
            # provider is configured by openai_base_url instead.
            upstream = config.get("openai_base_url") if provider == "openai" else definition.get("base_url")
            routing = None
            if provider == "openai" or definition.get("requires_openai_auth"):
                account = await self.rpc("account/read", {"refreshToken": False})
                kind = (account.get("account") or {}).get("type")
                routing = account.get("workspaceRouting")
                if not upstream:
                    upstream = "https://chatgpt.com/backend-api/codex" if kind == "chatgpt" else "https://api.openai.com/v1"
            if not upstream:
                raise NativeError("unsupported_native_provider")
            if routing:
                origin = urlsplit(routing["backendOrigin"])
                if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.path not in ("", "/") or origin.query or origin.fragment:
                    raise NativeError("unsupported_native_routing")
                original = urlsplit(upstream)
                bootstrap = urlsplit(config.get("chatgpt_base_url") or "https://chatgpt.com/backend-api")
                if upstream != "https://chatgpt.com/backend-api/codex" and (original.scheme, original.netloc) not in (
                    (origin.scheme, origin.netloc), (bootstrap.scheme, bootstrap.netloc)
                ):
                    routing = None
            if routing:
                upstream = routing["backendOrigin"].rstrip("/") + urlsplit(upstream).path
                self.transport = ProviderTransport(self, upstream, connect=True)
                # Workspace routing is enforced by the native account owner.
                # Keep its destination/config unchanged and restart this
                # threadless bootstrap process with transport-only proxy/CA.
                self.process.stdin.close()
                try:
                    await asyncio.wait_for(self.process.wait(), 3)
                except TimeoutError:
                    self.process.kill()
                    await self.process.wait()
                await self.read_task
                self.child_environment.update(self.transport.child_environment())
                await self.initialize(command)
                current = await self.rpc("account/read", {"refreshToken": False})
                if current.get("workspaceRouting") != routing:
                    raise NativeError("native_account_changed")
                overrides = {}
            else:
                self.transport = ProviderTransport(self, upstream)
                override = "openai_base_url" if provider == "openai" else f"model_providers.{provider}.base_url"
                overrides = {override: self.transport.url}
            result = await self.rpc("thread/start", {"cwd": self.cwd, **self.thread_options, "config": overrides})
            if result.get("modelProvider") != provider:
                raise NativeError("unsupported_native_routing")
            self.native_id = result["thread"]["id"]
            # Listing tests the actual native trust computation and honors
            # policies that disable hooks rather than assuming CLI injection.
            listing = await self.rpc("hooks/list", {"cwds": [self.cwd]})
            own = [hook for group in listing.get("data", []) for hook in group.get("hooks", [])
                   if hook.get("source") == "sessionFlags" and hook.get("command") in
                   (self.hook_command("PreToolUse"), self.hook_command("PostToolUse"))]
            if len(own) != 2 or any(not hook.get("enabled") or hook.get("trustStatus") != "trusted" for hook in own):
                raise NativeError("native_hooks_unavailable")
            self.started.set()
            return self.info()
        except BaseException:
            await self.close()
            raise

    async def initialize(self, command):
        await self.spawn(command)
        await self.rpc("initialize", {"clientInfo": {"name": "openaidr-managed", "version": "1"},
                                      "capabilities": {"experimentalApi": True}})
        await self.send({"method": "initialized"})

    async def rpc(self, method, params):
        ident = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        try:
            await self.send({"id": ident, "method": method, "params": params})
            return await asyncio.wait_for(future, 30)
        finally:
            self.pending.pop(ident, None)

    async def message(self, message):
        ident = message.get("id")
        if "method" not in message and ident in self.pending:
            future = self.pending[ident]
            if not future.done():
                if "error" in message:
                    future.set_exception(NativeError("native_rpc_rejected"))
                else:
                    future.set_result(message.get("result", {}))
            return
        method, params = message.get("method"), message.get("params", {})
        if ident is not None:
            self.task(self.permission(ident, method, params), callback=True)
            return
        if method == "item/completed":
            item = params.get("item", {})
            if item.get("type") == "agentMessage":
                self.queue_display(self.assistant_text, item["id"], item.get("text", ""))
            elif item.get("type") == "commandExecution":
                call = self.calls.get(item.get("id"))
                if call and not call["completion"].done():
                    code = item.get("exitCode")
                    if type(code) is int:
                        call["completion"].set_result(NativeOutcome("succeeded" if code == 0 else "failed", code))
                output = item.get("aggregatedOutput")
                if isinstance(output, str) and output:
                    self.queue_display(self.tool_display, item["id"], output)
        elif method == "turn/completed":
            status = params.get("turn", {}).get("status")
            self.task(self.finish_turn("completed" if status == "completed" else "cancelled" if status == "interrupted" else "failed"))

    async def tool_display(self, ident, text):
        ready = self.result_ready.setdefault(ident, asyncio.get_running_loop().create_future())
        held = await asyncio.shield(ready)
        if held is None or "display" not in held.deliveries or held.raw != text.encode():
            held = self.action("display-result:" + ident, "tool_output", text,
                               tool=self.calls.get(ident, {}).get("name", "native_result"), call_id=ident,
                               deliveries=("display",))
        async def release(_):
            await self.display("tool", text)
        await self.deliver(held, "display", release)

    async def permission(self, ident, method, params):
        if method in ("item/commandExecution/requestApproval", "item/fileChange/requestApproval"):
            values = params.get("availableDecisions") or ["accept", "acceptForSession", "decline", "cancel"]
            cancel = "cancel"
            choices = [{"label": value if isinstance(value, str) else json.dumps(value), "value": value} for value in values]
            request = {"id": ident, "method": method, "tool": "native command" if "commandExecution" in method else "native file change",
                       "input": params.get("command", params.get("reason", "")), "cwd": params.get("cwd", self.cwd),
                       "choices": choices, "cancel": cancel}
            answer = await self.approval_choice(request)
            if answer not in values:
                answer = cancel
            await self.send({"id": ident, "result": {"decision": answer}})
        elif method == "item/permissions/requestApproval":
            cancel = {"permissions": {}, "scope": "turn"}
            values = [cancel, {"permissions": params["permissions"], "scope": "turn"},
                      {"permissions": params["permissions"], "scope": "session"}]
            request = {"id": ident, "method": method, "input": params["permissions"], "cwd": params.get("cwd"),
                       "choices": [{"label": label, "value": value} for label, value in zip(("Deny", "Allow for turn", "Allow for session"), values)], "cancel": cancel}
            answer = await self.approval_choice(request)
            await self.send({"id": ident, "result": answer if answer in values else cancel})
        else:
            # Unsupported host UI requests are reported, never autoapproved.
            await self.send({"id": ident, "error": {"code": -32601, "message": "Managed host request is unsupported"}})

    async def submit(self, prompt):
        if not self.attached.is_set() or self.closed:
            raise NativeError("native_not_attached")
        async with self.turn_lock:
            self.turn_status = "completed"
            self.turn_id = str(uuid.uuid4())
            self.turn_done = asyncio.get_running_loop().create_future()
            held = self.action("prompt:" + self.turn_id, "prompt", prompt)
            async def release(_):
                value = await self.rpc("turn/start", {"threadId": self.native_id,
                    "input": [{"type": "text", "text": prompt, "text_elements": []}]})
                self.turn_id = value["turn"]["id"]
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
        if self.process and self.process.returncode is None and self.native_id and self.turn_id:
            try:
                await asyncio.wait_for(self.rpc("turn/interrupt", {"threadId": self.native_id, "turnId": self.turn_id}), 3)
            except (Exception, asyncio.CancelledError):
                pass
        if self.turn_done and not self.turn_done.done():
            self.turn_done.set_result("cancelled" if self.turn_status == "completed" else self.turn_status)
