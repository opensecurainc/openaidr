"""OpenAIDR pre-call policy plugin for the LiteLLM proxy."""

import asyncio
import json
import os
import re
import ssl
from dataclasses import dataclass, field
from time import monotonic
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

from .redact import contains_secret

MAX_BODY = 64 << 10
MAX_RESPONSE = 8 << 10
MAX_CHECKS = 32
MAX_OUTCOMES = 128
HEARTBEAT_SECONDS = 30
CAPTURE_SECONDS = 60
ROUTE = "/v1/chat/completions"


@dataclass(frozen=True)
class Settings:
    backend_url: str
    credential: str = field(repr=False)
    node_id: str
    capture_content: bool = False
    timeout_ms: int = 1000
    ca_file: str | None = None

    def __post_init__(self):
        url = urlsplit(self.backend_url)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("OPENAIDR_BACKEND_URL must be an HTTPS origin")
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError("invalid backend port")
        if not re.fullmatch(r"oagt_[A-Za-z0-9_-]{43}", self.credential):
            raise ValueError("invalid OPENAIDR_GATEWAY_TOKEN")
        if not label(self.node_id) or len(self.node_id) > 128:
            raise ValueError("OPENAIDR_NODE_ID must be a non-secret identifier of at most 128 characters")
        if type(self.capture_content) is not bool or type(self.timeout_ms) is not int or not 1 <= self.timeout_ms <= 2000:
            raise ValueError("capture must be boolean and timeout must be 1 to 2000 ms")

    @classmethod
    def from_env(cls):
        capture = os.environ.get("OPENAIDR_CAPTURE_CONTENT", "false")
        if capture not in ("true", "false"):
            raise ValueError("OPENAIDR_CAPTURE_CONTENT must be true or false")
        return cls(backend_url=os.environ["OPENAIDR_BACKEND_URL"],
                   credential=os.environ["OPENAIDR_GATEWAY_TOKEN"], node_id=os.environ["OPENAIDR_NODE_ID"],
                   capture_content=capture == "true", timeout_ms=int(os.environ.get("OPENAIDR_TIMEOUT_MS", "1000")),
                   ca_file=os.environ.get("OPENAIDR_CA_FILE") or None)


def label(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 256
            or any(ord(c) < 32 for c in value)):
        return ""
    try:
        value.encode("utf-8")
        return "" if contains_secret(value) else value
    except (UnicodeError, RecursionError):
        return ""


def uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def messages(data, capture):
    if not capture:
        return [], "capture_disabled"
    if any(data.get(key) for key in ("tools", "tool_choice", "functions", "function_call", "audio", "extra_body",
                                      "response_format", "prediction", "system", "prompt", "instructions", "input")):
        return [], "unsupported_content"
    if data.get("modalities") not in (None, ["text"]):
        return [], "unsupported_content"
    values = data.get("messages")
    if not isinstance(values, list) or not 1 <= len(values) <= 128:
        return [], "unsupported_content"
    result, size = [], 0
    for message in values:
        if (not isinstance(message, dict) or set(message) != {"role", "content"}
                or message["role"] not in ("system", "developer", "user", "assistant", "tool")
                or not isinstance(message["content"], str) or "\x00" in message["content"]):
            return [], "unsupported_content"
        content = message["content"]
        size += len(content)
        if size > MAX_BODY:
            return [], "oversized"
        try:
            content.encode("utf-8")
            if contains_secret(content):
                return [], "content_redacted"
        except (UnicodeError, RecursionError):
            return [], "unsupported_content"
        result.append({"role": message["role"], "content": content})
    return result, "available"


class OpenAIDRPlugin(CustomLogger):
    enforces_request_content = True

    def __init__(self, settings, version, gateway_version, *, transport=None):
        super().__init__(turn_off_message_logging=True)
        self.settings = settings
        self.version, self.gateway_version = version, label(gateway_version)[:80]
        self._transport = transport
        self._client = None
        self._worker = None
        self._queue = asyncio.Queue(maxsize=MAX_OUTCOMES)
        self._capture_until = 0
        self._connected = False
        self._metrics_supported = False
        self._observed = False
        self._active = 0
        self.dropped_events = 0

    async def start(self):
        if self._worker is not None and not self._worker.done():
            return
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.settings.backend_url.rstrip("/"),
                headers={"Authorization": "Bearer " + self.settings.credential},
                verify=ssl.create_default_context(cafile=self.settings.ca_file),
                trust_env=False, follow_redirects=False, timeout=self.settings.timeout_ms / 1000,
                limits=httpx.Limits(max_connections=MAX_CHECKS + 1, max_keepalive_connections=8),
                transport=self._transport,
            )
        self._worker = asyncio.create_task(self._run(), name="openaidr-plugin-telemetry")

    async def close(self):
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._connected, self._capture_until = False, 0

    async def _post(self, route, data):
        async with asyncio.timeout(self.settings.timeout_ms / 1000):
            async with self._client.stream("POST", "/ingest/v1/gateway-" + route, json=data) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=MAX_RESPONSE + 1):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE:
                        raise ValueError("oversized gateway response")
                value = json.loads(body)
                if not isinstance(value, dict):
                    raise ValueError("invalid gateway response")
                return response.status_code, value

    async def _heartbeat(self):
        started = monotonic()
        try:
            status, value = await self._post("heartbeats", {
                "kind": "litellm",
                "node_id": self.settings.node_id, "plugin_version": self.version,
                "gateway_version": self.gateway_version, "coverage": "observed_only",
                "routes": [{"route_id": ROUTE, "protocol": "openai.chat"}] if self._observed else [],
                "dropped_events": self.dropped_events,
            })
            if (status != 200 or value.get("kind") != "litellm" or not uuid(value.get("gateway_id"))
                    or value.get("enabled") is not True or type(value.get("capture_content")) is not bool
                    or value.get("mode") not in ("shadow", "enforce")
                    or type(value.get("version")) is not int or value["version"] < 1):
                raise ValueError("invalid gateway grant")
            self._connected = True
            self._metrics_supported = value.get("guardrail_metrics") is True
            self._capture_until = started + CAPTURE_SECONDS if value["capture_content"] else 0
        except Exception:
            self._connected, self._capture_until = False, 0
            self._metrics_supported = False
            self.dropped_events += 1

    async def _run(self):
        next_heartbeat = 0
        try:
            while True:
                if monotonic() >= next_heartbeat:
                    await self._heartbeat()
                    next_heartbeat = monotonic() + HEARTBEAT_SECONDS
                try:
                    receipt = await asyncio.wait_for(self._queue.get(), max(0, next_heartbeat - monotonic()))
                except TimeoutError:
                    continue
                try:
                    status, value = await self._post("outcomes", receipt)
                    if status != 200 or value.get("accepted") is not True or value.get("request_id") != receipt["request_id"]:
                        self.dropped_events += 1
                except Exception:
                    self.dropped_events += 1
                finally:
                    self._queue.task_done()
        finally:
            self._connected, self._capture_until = False, 0
            self._metrics_supported = False
            await self._client.aclose()
            self._client = None

    def _record(self, payload, started, *, check_id=None, blocked=False, failure="", succeeded=False):
        receipt = {k: v for k, v in payload.items() if k not in ("messages", "availability", "timeout_ms")}
        duration = max(0, (monotonic() - started) * 1000)
        receipt.update(outcome="blocked" if blocked else "unconfirmed" if succeeded else "fail_open",
                       status_code=403 if blocked else None, latency_ms=duration if blocked else None)
        if self._metrics_supported:
            receipt["guardrail_e2e_ms"] = duration
        if check_id:
            receipt["check_id"] = check_id
        if failure:
            receipt["failure_reason"] = failure
        try:
            self._queue.put_nowait(receipt)
        except asyncio.QueueFull:
            self.dropped_events += 1

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if call_type not in ("completion", "acompletion"):
            return data
        started = monotonic()
        payload = None
        try:
            await self.start()
            if not self._connected:
                self.dropped_events += 1
                return data
            self._observed = True
            identity = label(getattr(user_api_key_dict, "user_id", None))
            consumer = "user:" + identity if identity else ""
            consumer_name = label(getattr(user_api_key_dict, "user_email", None))
            if not consumer:
                identity = label(getattr(user_api_key_dict, "team_id", None))
                consumer = "team:" + identity if identity else ""
                consumer_name = label(getattr(user_api_key_dict, "team_alias", None))
            consumer = label(consumer)
            key_metadata = getattr(user_api_key_dict, "metadata", None)
            application = label(key_metadata.get("application_name")) if isinstance(key_metadata, dict) else ""
            captured, availability = messages(data, self.settings.capture_content and monotonic() < self._capture_until)
            payload = {"request_id": str(uuid4()), "node_id": self.settings.node_id,
                       "route_id": ROUTE, "consumer_id": consumer, "model": label(data.get("model")),
                       "protocol": "openai.chat", "stream": data.get("stream") is True,
                       "messages": captured, "availability": availability, "timeout_ms": self.settings.timeout_ms}
            if consumer and consumer_name:
                payload["consumer_name"] = consumer_name
            if application:
                payload["application_name"] = application
            if len(json.dumps(payload, ensure_ascii=True).encode()) > MAX_BODY:
                payload.update(messages=[], availability="oversized")
            if self._active >= MAX_CHECKS:
                self._record(payload, started, failure="backend_unavailable")
                return data
            self._active += 1
            try:
                async with asyncio.timeout(max(0, self.settings.timeout_ms / 1000 - (monotonic() - started))):
                    status, reply = await self._post("checks", payload)
                check_id = reply.get("id") if uuid(reply.get("id")) and reply.get("request_id") == payload["request_id"] else None
                if status != 200:
                    failure = payload["availability"] if payload["availability"] != "available" else "backend_unavailable"
                    if status == 503 and check_id and reply.get("status") == "unavailable":
                        failure = ""  # Preserve the backend's more precise assessment failure.
                    self._record(payload, started, check_id=check_id, failure=failure)
                    return data
                if (not check_id or reply.get("status") != "evaluated" or payload["availability"] != "available"
                        or reply.get("mode") not in ("shadow", "enforce")
                        or type(reply.get("settings_version")) is not int or reply["settings_version"] < 1
                        or type(reply.get("policy_version")) is not int or reply["policy_version"] < 0
                        or reply.get("evaluated_decision") not in ("allow", "deny")
                        or reply.get("returned_decision") != ("allow" if reply["mode"] == "shadow" else reply["evaluated_decision"])
                        or monotonic() - started >= self.settings.timeout_ms / 1000):
                    raise ValueError("invalid gateway decision")
                blocked = reply["returned_decision"] == "deny"
                if blocked:
                    self._record(payload, started, check_id=check_id, blocked=True)
                elif self._metrics_supported:
                    self._record(payload, started, check_id=check_id, succeeded=True)
            finally:
                self._active -= 1
        except (TimeoutError, httpx.TimeoutException):
            if payload is not None:
                self._record(payload, started, failure="timeout")
            return data
        except httpx.RequestError:
            if payload is not None:
                self._record(payload, started, failure="backend_unavailable")
            return data
        except Exception:
            if payload is not None:
                self._record(payload, started, failure="invalid_response")
            else:
                self.dropped_events += 1
            return data
        if blocked:
            raise HTTPException(status_code=403, detail="Request blocked by OpenAIDR")
        return data
