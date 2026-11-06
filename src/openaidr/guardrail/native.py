"""Small shared lifecycle and exact boundary helpers for the two native clients."""

import asyncio
import copy
from dataclasses import replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import sys
import uuid

from openaidr.core.event import now
from openaidr.core.toolmap import map_tool

from .gate import HeldBoundary, NativeOutcome
from .hook_bridge import ENVIRONMENT_KEY, HOLD_SECONDS, MAX_MESSAGE, denied
from .journal import canonical


class NativeError(RuntimeError):
    """The code is safe for presentation; native errors never cross this API."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


PINS = {
    "codex": ("codex-cli 0.160.0", {
        "112fae7a5a1223e673c8a1791d32338f37df8b527ff1159bb8adac6c4dbf1b4b",
    }),
    "claude": ("2.1.287 (Claude Code)", {
        "6eab8333fe2121553100d8f40bfada384a3e989b94f947e18ba6677a6fcb41ea",
    }),
}
MAX_ACTIONS = 4096
MAX_ACTIVE_BYTES = 64 * 1024 * 1024


def launch_attribute(environment):
    value = environment.get("OPENAIDR_MANAGED_LAUNCH_ID")
    if not value:
        return None
    try:
        value = str(uuid.UUID(value))
    except ValueError:
        raise NativeError("invalid_managed_launch") from None
    key = "openaidr.managed.launch_id"
    items = [part for part in environment.get("OTEL_RESOURCE_ATTRIBUTES", "").split(",")
             if part and part.partition("=")[0].strip() != key]
    return ",".join([*items, key + "=" + value])


async def executable(agent, environment):
    value = shutil.which(agent, path=environment.get("PATH"))
    if not value:
        raise NativeError("native_binary_missing")
    binary = Path(value).resolve()
    expected, digests = PINS[agent]
    def digest():
        with binary.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    if await asyncio.to_thread(digest) not in digests:
        raise NativeError("unsupported_native_binary")
    process = await asyncio.create_subprocess_exec(
        str(binary), "--version", env=environment,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 10)
    except (TimeoutError, asyncio.CancelledError) as exc:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise NativeError("native_version_failed") from None
    if process.returncode or output.decode(errors="replace").strip() != expected:
        raise NativeError("unsupported_native_binary")
    return str(binary), expected


class NativeSession:
    def __init__(self, agent, options):
        self.agent = agent
        self.product = {"codex": "codex-cli", "claude": "claude-code"}[agent]
        self.cwd = str(Path(options["cwd"]).resolve(strict=True))
        self.environment = dict(options["environment"])
        self.arguments = tuple(options.get("native_args", ()))
        self.directory = Path(options["transient_directory"])
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.stat().st_mode & 0o077:
            raise NativeError("private_directory_required")
        self.process = None
        self.process_started = False
        self.tasks = set()
        self.pending = {}
        self.write_lock = asyncio.Lock()
        self.turn_lock = asyncio.Lock()
        self.native_id = None
        self.gate = None
        self.closed = False
        self.turn_id = None
        self.turn_done = None
        self.turn_status = "completed"
        self.sequence = 0
        self.actions = {}
        self.calls = {}
        self.hook_replies = {}
        self.hook_inflight = {}
        self.hook_inputs = {}
        self.started = asyncio.Event()
        self.attached = asyncio.Event()
        self.bridge = None
        self.transport = None
        self.read_task = None
        self.callback_tasks = set()
        self.gaps = ("unsupported_boundary",)
        self.provider_messages = {}
        self.model_results = {}
        self.displays = []
        self.result_ready = {}
        self.denied_results = set()
        self.bridge_tasks = set()
        self.transport_calls = {}
        self.execution_tasks = set()
        self.close_task = None
        self.identity_key = secrets.token_bytes(32)
        self.retired_actions = set()
        self.active_bytes = 0

    def task(self, coro, *, callback=False):
        task = asyncio.create_task(coro)
        collection = self.callback_tasks if callback else self.tasks
        collection.add(task)
        task.add_done_callback(collection.discard)
        # Exceptions remain controlled and are collected at close; they must
        # never become an asyncio raw native-payload diagnostic.
        task.add_done_callback(lambda value: None if value.cancelled() else value.exception())
        return task

    def execution(self):
        task = asyncio.current_task()
        self.execution_tasks.add(task)
        task.add_done_callback(self.execution_tasks.discard)

    async def setup(self):
        self.binary, self.version = await executable(self.agent, self.environment)
        self.bridge_token = secrets.token_urlsafe(32)
        self.bridge = await asyncio.start_server(self._bridge, "127.0.0.1", 0, limit=MAX_MESSAGE + 1)
        self.bridge_path = self.directory / (self.agent + "-bridge.json")
        with open(self.bridge_path, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            json.dump({"agent": self.agent, "port": self.bridge.sockets[0].getsockname()[1],
                       "token": self.bridge_token}, stream)
        self.child_environment = dict(self.environment, **{ENVIRONMENT_KEY: str(self.bridge_path)})
        if attributes := launch_attribute(self.environment):
            self.child_environment["OTEL_RESOURCE_ATTRIBUTES"] = attributes

    def hook_command(self, event):
        if getattr(sys, "frozen", False):
            return shlex.join([sys.executable, "managed-hook", self.agent, event])
        return shlex.join([sys.executable, "-m", "openaidr.guardrail.hook_bridge", self.agent, event])

    def attach(self, *, gate, context, display, native_approval, observe, status):
        if self.gate is not None or self.native_id is None or self.closed:
            raise NativeError("invalid_native_attachment")
        self.gate, self.context, self.display = gate, context, display
        self.native_approval, self.observe, self.status = native_approval, observe, status
        self.attached.set()

    def info(self):
        return {"native_id": self.native_id, "product": self.product, "version": self.version,
                "coverage": {"prompt": "held", "tool_call": "observable_native_hooks",
                             "tool_output": "complete_transport_and_observable_hooks",
                             "assistant_response": "complete_managed_display",
                             "native_settings": "preserved"},
                "boundaries": ("prompt", "tool_call", "tool_output", "assistant_response"),
                "gaps": self.gaps}

    async def approval_choice(self, request):
        try:
            return await self.native_approval(request) if self.gate else request["cancel"]
        except (Exception, asyncio.CancelledError):
            # Losing the controlling terminal or host callback is a native
            # cancellation, never an implicit permission or a hanging request.
            return request["cancel"]

    async def transport_abandoned(self):
        self.turn_status = "blocked"
        await self.cancel()

    def action(self, key, boundary, value, *, tool=None, call_id=None, deliveries=("native",)):
        if not self.gate:
            raise NativeError("native_not_attached")
        if len(key) > 1024 or call_id is not None and len(call_id) > 512:
            raise NativeError("invalid_native_identity")
        raw = value.encode() if isinstance(value, str) else canonical(value)
        if key in self.retired_actions:
            raise NativeError("native_identity_retired")
        if key in self.actions:
            held = self.actions[key]
            if held.raw != raw or held.deliveries != deliveries:
                raise NativeError("native_identity_changed")
            return held
        if len(self.actions) + len(self.retired_actions) >= MAX_ACTIONS or self.active_bytes + len(raw) > MAX_ACTIVE_BYTES:
            raise NativeError("native_capacity_exceeded")
        binding = self.gate.journal.binding
        namespace = uuid.UUID(binding["epoch_id"])
        logical = str(uuid.uuid5(namespace, self.product + ":" + key))
        event_id = str(uuid.uuid5(namespace, "event:" + key))
        self.sequence += 1
        event = {"id": event_id, "time": now(),
                 "kind": {"prompt": "prompt", "tool_call": "tool.call", "tool_output": "tool.result",
                          "assistant_response": "response"}[boundary],
                 "agent": {"product": self.product, "version": self.version},
                 "session": {"id": binding["session_id"], "registration_id": binding["registration_id"]},
                 "evidence": {"version": 1, "logical_id": logical, "observation_id": event_id,
                              "stream_id": binding["epoch_id"], "sequence": self.sequence,
                              "part": 0, "gaps": []}}
        if binding["registration_id"] is None:
            event["session"].pop("registration_id")
        if tool:
            event["tool"] = {"name": tool, "call_id": call_id or key,
                             "input" if boundary == "tool_call" else "output": copy.deepcopy(value)}
            if boundary == "tool_call" and isinstance(value, dict):
                mapped = map_tool(self.product, tool, value)
                if mapped:
                    # Tool mapping adds policy-visible paths/commands only;
                    # the immutable exact native arguments stay in tool.input.
                    for field in ("command", "file", "network"):
                        if field in mapped[0]:
                            event[field] = mapped[0][field]
                    event["kind"] = mapped[0]["kind"]
        else:
            event["text"] = value if isinstance(value, str) else raw.decode()
        matched = self.calls.get(call_id, {}).get("event") if call_id else None
        if boundary == "tool_output" and matched is None:
            event["evidence"]["gaps"].append("missing_tool_call")
        context = self.context(event, matched)
        owned_bytes = len(raw) + len(canonical(event)) + len(canonical(context))
        if self.active_bytes + owned_bytes > MAX_ACTIVE_BYTES:
            raise NativeError("native_capacity_exceeded")
        held = HeldBoundary(logical, boundary, raw, event, copy.deepcopy(context),
                            delivery_id=deliveries[0], deliveries=deliveries)
        self.actions[key] = held
        self.active_bytes += owned_bytes
        return held

    def digest(self, value):
        return hmac.digest(self.identity_key, value, "sha256")

    async def retire_turn(self):
        # A completed SDK turn may precede the final gate's bookkeeping. Join
        # every registered consumer before dropping its exact raw arguments.
        for call in [*self.calls.values(), *self.transport_calls.values()]:
            if not call["completion"].done():
                call["completion"].set_result(NativeOutcome("uncertain"))
        active = self.callback_tasks | (self.tasks - {self.read_task})
        await asyncio.gather(*active, return_exceptions=True)
        self.retired_actions.update(self.actions)
        self.actions.clear()
        self.calls.clear()
        self.transport_calls.clear()
        self.provider_messages.clear()
        self.result_ready.clear()
        self.displays.clear()
        if offsets := getattr(self, "message_offsets", None):
            offsets.clear()
        self.active_bytes = 0

    async def deliver(self, held, delivery, callback):
        async def release(raw):
            await callback(raw)
            return NativeOutcome("succeeded")
        result = await self.gate.gate(replace(held, delivery_id=delivery), release)
        if result.status != "succeeded":
            self.turn_status = "uncertain" if result.status == "uncertain" else "blocked"
        return result

    async def provider_request(self, payload):
        if not self.attached.is_set() or not self.turn_id or self.closed or self.turn_status == "blocked":
            raise NativeError("native_not_attached")
        items = []
        if self.agent == "codex":
            for item in payload.get("input", []):
                if isinstance(item, dict) and item.get("type") in ("function_call_output", "custom_tool_call_output"):
                    items.append((item.get("call_id"), item.get("output")))
        else:
            for message in payload.get("messages", []):
                content = message.get("content", [])
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "tool_result":
                            items.append((item.get("tool_use_id"), item.get("content")))
        targets = []
        new = []
        for call_id, value in items:
            if not isinstance(call_id, str):
                raise NativeError("invalid_native_result")
            if call_id in self.denied_results:
                raise NativeError("managed_boundary_blocked")
            raw = self.digest(canonical(value))
            previous = self.model_results.get(call_id)
            if previous:
                if previous[0] != raw or previous[1] != "succeeded":
                    raise NativeError("native_result_uncertain")
                # Native requests repeat previously approved history. That
                # history is context, not a new result or approval consume.
                continue
            call = self.calls.get(call_id, {})
            transport_call = self.transport_calls.get(call_id)
            if transport_call and not transport_call["completion"].done():
                # Code mode reports completion in its own result envelope;
                # an early running response is not a completed execution.
                if self.agent == "codex":
                    first = value[0].get("text", "") if isinstance(value, list) and value and isinstance(value[0], dict) else value
                    outcome = "succeeded" if isinstance(first, str) and first.startswith("Script completed") else "failed" if isinstance(first, str) and first.startswith("Script failed") else "uncertain"
                    transport_call["completion"].set_result(NativeOutcome(outcome))
            held = self.action("model-result:" + call_id, "tool_output", value,
                               tool=call.get("name", "native_result"), call_id=call_id,
                               deliveries=("model",))
            self.model_results[call_id] = (raw, "pending")
            new.append(call_id)
            targets.append((held, "model"))
        async def finished(outcome):
            for call_id in new:
                self.model_results[call_id] = (self.model_results[call_id][0], outcome)
        return await DeliveryBatch.start(self, targets, finished)

    def auxiliary_request(self, payload):
        if self.agent != "claude" or payload.get("tools"):
            return False
        system = payload.get("system", "")
        if isinstance(system, list):
            texts = [item.get("text", "") for item in system if isinstance(item, dict)]
            system = "\n".join(text for text in texts if not text.startswith("x-anthropic-billing-header:"))
        # This pin's native safety monitor is not an assistant message or a
        # permission grant. Keep its response out of both user display and
        # guardrail scoring. Native tool hooks still gate the underlying call.
        return isinstance(system, str) and system.startswith("You are a security monitor for autonomous AI coding agents.")

    async def provider_response(self, data, content_type):
        from .transport import completed_response
        response = completed_response(data, content_type, self.agent)
        targets = []
        items = response.get("output", []) if self.agent == "codex" else response.get("content", [])
        for index, item in enumerate(items):
            kind = item.get("type")
            if kind == "message" and item.get("role") == "assistant":
                text = "".join(part.get("text", "") for part in item.get("content", []) if part.get("type") == "output_text")
                ident = str(item.get("id") or response.get("id"))
            elif kind == "text" and self.agent == "claude":
                text = item.get("text", "")
                ident = str(response.get("id")) + ":" + str(index)
            elif kind == "custom_tool_call" or self.agent == "claude" and kind == "tool_use":
                # Code mode's outer script is a real native action in addition
                # to observable nested local calls. Hosted tools remain gaps.
                ident = str(item.get("call_id") or item.get("id"))
                held = self.action("provider-call:" + ident, "tool_call", item.get("input", ""),
                                   tool=item.get("name", "native_tool"), call_id=ident)
                call = {"event": held.event, "held": held, "name": item.get("name", "native_tool"),
                        "completion": asyncio.get_running_loop().create_future()}
                self.calls[ident] = self.transport_calls[ident] = call
                targets.append((held, "native", call["completion"]))
                continue
            else:
                continue
            if not isinstance(text, str):
                raise NativeError("invalid_native_text")
            held = self.action("message:" + ident, "assistant_response", text,
                               deliveries=("native", "display"))
            self.provider_messages[ident] = held
            targets.append((held, "native"))
        return await DeliveryBatch.start(self, targets)

    async def assistant_text(self, ident, text):
        # Native IDs are authoritative. Do not transfer an approval by fuzzy
        # text/substring matching across different native messages.
        held = self.provider_messages.get(ident)
        if held is None:
            held = self.action("display-message:" + ident, "assistant_response", text,
                               deliveries=("display",))
        elif held.raw != text.encode():
            raise NativeError("native_identity_changed")
        async def release(_):
            await self.display("assistant", text)
        result = await self.deliver(held, "display", release)
        if result.status != "succeeded":
            await self.cancel()

    def queue_display(self, callback, *arguments):
        previous = self.displays[-1] if self.displays else None
        async def ordered():
            if previous:
                await asyncio.shield(previous)
            return await callback(*arguments)
        task = self.task(ordered(), callback=True)
        self.displays.append(task)

    async def finish_turn(self, status):
        # The reader must remain free for permission responses while display
        # gates wait for owner approval.
        for future in self.result_ready.values():
            if not future.done():
                future.set_result(None)
        values = await asyncio.gather(*self.displays, return_exceptions=True)
        if self.turn_status == "completed" and any(isinstance(value, BaseException) for value in values):
            self.turn_status = "failed"
        self.displays.clear()
        for call in [*self.calls.values(), *self.transport_calls.values()]:
            if not call["completion"].done():
                call["completion"].set_result(NativeOutcome("uncertain"))
        await asyncio.gather(*self.execution_tasks, return_exceptions=True)
        if self.turn_done and not self.turn_done.done():
            self.turn_done.set_result(self.turn_status if self.turn_status != "completed" else status)

    async def _bridge(self, reader, writer):
        event = "PreToolUse"
        authenticated = False
        task = asyncio.current_task()
        if len(self.bridge_tasks) >= 32:
            writer.close()
            await writer.wait_closed()
            return
        self.bridge_tasks.add(task)
        hold = lost = None
        try:
            raw = await asyncio.wait_for(reader.readline(), 5)
            if len(raw) > MAX_MESSAGE:
                raise ValueError("oversized bridge")
            request = json.loads(raw)
            event = request.get("event", event)
            if not hmac.compare_digest(str(request.get("token", "")), self.bridge_token) or request.get("agent") != self.agent:
                raise ValueError("foreign bridge")
            authenticated = True
            if not request.get("owned"):
                result = {}
            else:
                # The deadline expires before the native timeout. A lost hold
                # is an explicit deny and interrupts the owning turn.
                hold = asyncio.create_task(self.hook(event, request["payload"]))
                lost = asyncio.create_task(reader.read(1))
                done, _ = await asyncio.wait((hold, lost), timeout=HOLD_SECONDS, return_when=asyncio.FIRST_COMPLETED)
                if hold not in done:
                    raise NativeError("native_hook_abandoned")
                result = hold.result()
            writer.write(canonical(result) + b"\n")
            await writer.drain()
        except (Exception, asyncio.CancelledError):
            try:
                writer.write(canonical(denied(event)) + b"\n")
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            if authenticated and self.turn_id and not self.closed:
                self.turn_status = "blocked"
                self.task(self.cancel())
        finally:
            for waiter in (hold, lost):
                if waiter and not waiter.done():
                    waiter.cancel()
            await asyncio.gather(*(waiter for waiter in (hold, lost) if waiter), return_exceptions=True)
            self.bridge_tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def hook(self, event, payload):
        if not self.attached.is_set() or self.closed:
            return denied(event)
        call_id = payload.get("tool_use_id") or payload.get("tool_call_id") or payload.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            return denied(event)
        key = (event, call_id)
        identity = canonical({name: payload.get(name) for name in (
            "session_id", "turn_id", "tool_name", "tool_input", "tool_response", "tool_result")})
        identity = self.digest(identity)
        if len(call_id) > 512 or key not in self.hook_inputs and len(self.hook_inputs) >= 2 * MAX_ACTIONS:
            raise NativeError("native_capacity_exceeded")
        if key in self.hook_inputs and self.hook_inputs[key] != identity:
            raise NativeError("native_identity_changed")
        self.hook_inputs[key] = identity
        if key in self.hook_replies:
            return self.hook_replies[key]
        if key in self.hook_inflight:
            return await asyncio.shield(self.hook_inflight[key])
        future = asyncio.get_running_loop().create_future()
        self.hook_inflight[key] = future
        try:
            result = await self._hook(event, payload, call_id)
            self.hook_replies[key] = result
            future.set_result(result)
            return result
        except BaseException:
            if not future.done():
                future.set_result(denied(event))
            raise
        finally:
            self.hook_inflight.pop(key, None)

    async def _hook(self, event, payload, call_id):
        name = payload.get("tool_name", "unknown")
        if event == "PreToolUse":
            value = payload.get("tool_input", {})
            native = self.transport_calls.get(call_id)
            if native and native["name"] == name and native["held"].raw == canonical(value):
                # The exact call crossed the already-held provider response.
                # This callback is the same action, not another approval.
                return {}
            held = self.action("call:" + call_id, "tool_call", value, tool=name, call_id=call_id)
            completion = asyncio.get_running_loop().create_future()
            permitted = asyncio.get_running_loop().create_future()
            self.calls[call_id] = {"event": held.event, "completion": completion, "name": name}
            self.result_ready.setdefault(call_id, asyncio.get_running_loop().create_future())
            async def release(_):
                self.execution()
                permitted.set_result({})  # Native permissions still apply.
                return await completion
            async def run():
                try:
                    result = await self.gate.gate(held, release)
                    if result.status == "blocked":
                        self.turn_status = "blocked"
                    return result
                finally:
                    if not permitted.done():
                        permitted.set_result(denied(event))
            task = self.task(run(), callback=True)
            try:
                return await permitted
            except asyncio.CancelledError:
                task.cancel()
                raise
        if event == "PostToolUse":
            call = self.calls.get(call_id)
            if call and not call["completion"].done():
                call["completion"].set_result(NativeOutcome("uncertain" if self.agent == "codex" else "succeeded"))
            value = payload.get("tool_response", payload.get("tool_result", {}))
            deliveries = ("native", "display") if self.agent == "codex" and isinstance(value, str) else ("native",)
            held = self.action("hook-result:" + call_id, "tool_output", value, tool=name, call_id=call_id,
                               deliveries=deliveries)
            ready = self.result_ready.setdefault(call_id, asyncio.get_running_loop().create_future())
            if not ready.done():
                ready.set_result(held)
            result = await self.deliver(held, "native", _nothing)
            if result.status == "succeeded":
                return {}
            # Claude PostToolUse block is feedback, not a result barrier. Stop
            # its turn and let transport/display independently withhold bytes.
            self.denied_results.add(call_id)
            self.task(self.cancel())
            return denied(event)
        return {}

    async def send(self, value):
        async with self.write_lock:
            if not self.process or self.process.returncode is not None:
                raise NativeError("native_process_ended")
            self.process.stdin.write(canonical(value) + b"\n")
            await self.process.stdin.drain()

    async def spawn(self, args):
        self.process_started = True
        starting = asyncio.create_task(asyncio.create_subprocess_exec(
            *args, cwd=self.cwd, env=self.child_environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=MAX_MESSAGE + 1,
            start_new_session=True,
        ))
        try:
            self.process = await asyncio.shield(starting)
        except asyncio.CancelledError:
            self.process = await starting
            self.read_task = self.task(self.read())
            raise
        self.read_task = self.task(self.read())

    async def read(self):
        try:
            while raw := await self.process.stdout.readline():
                if len(raw) > MAX_MESSAGE:
                    raise NativeError("oversized_native_message")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise NativeError("invalid_native_message")
                await self.message(message)
        except (Exception, asyncio.CancelledError):
            self.turn_status = "failed"
        finally:
            for task in tuple(self.callback_tasks):
                task.cancel()
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(NativeError("native_process_ended"))
            if self.turn_done and not self.turn_done.done():
                self.turn_done.set_result("failed")

    async def close(self):
        if self.close_task is None:
            self.closed = True
            self.close_task = asyncio.create_task(self._close())
        cancelled = False
        while not self.close_task.done():
            try:
                await asyncio.shield(self.close_task)
            except asyncio.CancelledError:
                cancelled = True
        result = self.close_task.result()
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def _close(self):
        failed = False
        if self.bridge:
            try:
                self.bridge.close()
            except OSError:
                failed = True
        try:
            await self.cancel()
        except (Exception, asyncio.CancelledError):
            failed = True
        try:
            if self.transport:
                await self.transport.close()
        except (Exception, asyncio.CancelledError):
            failed = True
        # Close admission before joining callbacks. A late native hook or
        # provider reply must not revive a gate after the launcher settles it.
        for task in tuple(self.bridge_tasks):
            task.cancel()
        await asyncio.gather(*self.bridge_tasks, return_exceptions=True)
        if self.process:
            try:
                self.process.stdin.close()
            except (OSError, ValueError):
                failed = True
            for action in (None, self.process.terminate, self.process.kill):
                if self.process.returncode is not None:
                    break
                if action:
                    try:
                        action()
                    except ProcessLookupError:
                        pass
                    except OSError:
                        failed = True
                try:
                    await asyncio.wait_for(self.process.wait(), 3)
                except (TimeoutError, OSError):
                    continue
            if self.process.returncode is None:
                failed = True
        while active := {task for task in self.tasks | self.callback_tasks if not task.done()}:
            for task in active:
                task.cancel()
            await asyncio.gather(*active, return_exceptions=True)
        if self.bridge:
            try:
                await self.bridge.wait_closed()
            except OSError:
                failed = True
        for name in ("bridge_path", "settings_path"):
            if path := getattr(self, name, None):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    failed = True
        self.actions.clear()
        self.calls.clear()
        self.transport_calls.clear()
        self.provider_messages.clear()
        self.result_ready.clear()
        self.displays.clear()
        self.active_bytes = 0
        if failed:
            raise NativeError("native_shutdown_failed")


async def _nothing(_):
    pass


class DeliveryBatch:
    """Authorize several items before the single transport write they share."""

    def __init__(self, session, finished):
        self.session, self.finished = session, finished
        self.done = asyncio.get_running_loop().create_future()
        self.tasks = []
        self.delivery_tasks = []

    @classmethod
    async def start(cls, session, targets, finished=None):
        batch = cls(session, finished)
        permits = []
        for target in targets:
            held, delivery = target[:2]
            completion = target[2] if len(target) == 3 else None
            permit = asyncio.get_running_loop().create_future()
            permits.append(permit)
            async def run(held=held, delivery=delivery, permit=permit, completion=completion):
                async def release(_):
                    if completion is not None:
                        session.execution()
                    if not permit.done():
                        permit.set_result(True)
                    result = await asyncio.shield(batch.done)
                    if completion is not None and result.outcome == "succeeded":
                        return await asyncio.shield(completion)
                    return result
                try:
                    return await session.gate.gate(replace(held, delivery_id=delivery), release)
                finally:
                    if not permit.done():
                        # A consumed or uncertain delivery cannot be replayed by
                        # retrying a provider request with a fresh callback.
                        permit.set_result(False)
            task = session.task(run(), callback=True)
            batch.tasks.append(task)
            if completion is None:
                batch.delivery_tasks.append(task)
        try:
            if permits and not all(await asyncio.gather(*permits)):
                session.turn_status = "blocked"
                await batch.finish("not_executed")
                session.task(session.cancel())
                raise NativeError("managed_boundary_blocked")
            return batch
        except BaseException:
            for task in batch.tasks:
                task.cancel()
            await asyncio.gather(*batch.tasks, return_exceptions=True)
            raise

    async def finish(self, outcome):
        if not self.done.done():
            self.done.set_result(NativeOutcome(outcome))
            if self.finished:
                await self.finished(outcome)
        await asyncio.gather(*self.delivery_tasks, return_exceptions=True)
