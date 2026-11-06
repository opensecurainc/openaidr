"""Loopback-only scripted Responses/Messages transport for real native clients.

This fixture replaces external inference, not wrapper or approval behavior.
"""

import base64
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import ssl
from threading import Condition, Event, Thread
from urllib.parse import urlsplit

import httpx


TOKENS = {
    "codex": "sk-synthetic-codex-native-fixture",
    "claude": "sk-ant-synthetic-native-fixture",
}


@dataclass(frozen=True)
class Text:
    value: str
    phase: str = "final_answer"


@dataclass(frozen=True)
class Call:
    name: str
    arguments: dict
    call_id: str = "fixture-call"


@dataclass(frozen=True)
class Code:
    value: str
    call_id: str = "fixture-code-call"


class FakeProvider:
    def __init__(
        self,
        case: Path,
        turns: list[list[Text | Call | Code]],
        *,
        product,
        split_first=False,
    ):
        self.case, self.turns, self.product = case, turns, product
        self.split_first = split_first
        self.requests = []
        self.model_requests = []
        self.auxiliary_requests = []
        self.headers = []
        self.unexpected = []
        self.condition = Condition()
        self.stream_started, self.stream_release = Event(), Event()
        if not split_first:
            self.stream_release.set()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.daemon_threads = True
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.case.mkdir(parents=True, exist_ok=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stream_release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "fixture provider did not stop"

    def wait_for_requests(self, count, timeout=5):
        with self.condition:
            assert self.condition.wait_for(
                lambda: len(self.model_requests) >= count, timeout
            ), "native client did not reach provider barrier"
            return list(self.model_requests)

    def record(self, path, payload, *, model=False, auxiliary=False):
        with self.condition:
            record = {"path": path, "body": payload}
            self.requests.append(record)
            if model:
                self.model_requests.append(record)
            if auxiliary:
                self.auxiliary_requests.append(record)
            with (self.case / "provider-requests.jsonl").open("a") as stream:
                stream.write(json.dumps(record) + "\n")
            self.condition.notify_all()
            return len(self.model_requests)

    def handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def respond(self, body, status=200):
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def reject(self):
                fixture.unexpected.append({"method": self.command, "path": self.path})
                self.respond({"error": "unsupported fixture endpoint"}, 403)

            def do_CONNECT(self):
                self.reject()

            def do_GET(self):
                if (
                    urlsplit(self.path).path == "/v1/responses"
                    and self.headers.get("Upgrade", "").lower() == "websocket"
                ):
                    return self.respond({"error": "use HTTP streaming"}, 426)
                if self.path == "/v1/models":
                    return self.respond(
                        {
                            "object": "list",
                            "data": [{"id": "gpt-6.1-sol", "object": "model"}],
                        }
                    )
                self.reject()

            def do_POST(self):
                path = urlsplit(self.path)
                if path.scheme or path.netloc:
                    return self.reject()
                token = TOKENS[fixture.product]
                credential_ok = (
                    self.headers.get("Authorization") == "Bearer " + token
                    or self.headers.get("x-api-key") == token
                )
                fixture.headers.append(
                    {
                        "synthetic_credential": credential_ok,
                        "literal_header": self.headers.get("X-User-Literal"),
                        "env_header": self.headers.get("X-User-Env"),
                        "anthropic_beta": self.headers.get("anthropic-beta"),
                        "anthropic_version": self.headers.get("anthropic-version"),
                    }
                )
                if not credential_ok:
                    return self.respond(
                        {"error": "non-fixture credential rejected"}, 403
                    )
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 1024 * 1024:
                    return self.respond({"error": "invalid fixture body size"}, 413)
                payload = json.loads(self.rfile.read(length))
                if path.path == "/v1/messages/count_tokens":
                    fixture.record(self.path, payload)
                    return self.respond({"input_tokens": 100})
                if path.path not in ("/v1/responses", "/v1/messages"):
                    return self.reject()
                auxiliary = (
                    "You are a security monitor for autonomous AI coding agents."
                    in str(payload.get("system"))
                )
                number = fixture.record(
                    self.path, payload, model=not auxiliary, auxiliary=auxiliary
                )
                if not auxiliary and number > len(fixture.turns):
                    return self.respond({"error": "fixture turn budget exhausted"}, 500)
                items = (
                    [Text("<block>no</block>")]
                    if auxiliary
                    else fixture.turns[number - 1]
                )
                if path.path == "/v1/responses":
                    frames = responses(items, number)
                else:
                    frames, message = messages(items, number, payload.get("model"))
                    if not payload.get("stream"):
                        return self.respond(message)
                encoded = [
                    f"event: {frame['type']}\ndata: {json.dumps(frame)}\n\n".encode()
                    for frame in frames
                ]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(sum(map(len, encoded))))
                self.end_headers()
                # A caller can prove held partial text is absent before allowing
                # the rest of the provider stream to finish.
                split = len(encoded)
                if fixture.split_first and number == 1 and not auxiliary:
                    split = min(
                        len(encoded) - 1,
                        next(
                            (
                                index + 1
                                for index, frame in enumerate(frames)
                                if frame["type"]
                                in ("response.output_text.delta", "content_block_delta")
                            ),
                            max(1, len(encoded) // 2),
                        ),
                    )
                self.wfile.write(b"".join(encoded[:split]))
                self.wfile.flush()
                fixture.stream_started.set()
                if split < len(encoded):
                    if not fixture.stream_release.wait(15):
                        return
                    self.wfile.write(b"".join(encoded[split:]))
                    self.wfile.flush()

        return Handler


def responses(items, number):
    output, frames = [], []
    response = {
        "id": f"resp_fixture_{number}",
        "object": "response",
        "status": "completed",
        "model": "gpt-6.1-sol",
        "output": output,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }
    frames.append(
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress", "output": []},
        }
    )
    for index, item in enumerate(items):
        ident = f"item_{number}_{index}"
        if isinstance(item, Text):
            value = {
                "id": ident,
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "phase": item.phase,
                "content": [
                    {"type": "output_text", "text": item.value, "annotations": []}
                ],
            }
            frames.append(
                {
                    "type": "response.output_item.added",
                    "output_index": index,
                    "item": {**value, "content": []},
                }
            )
            frames.append(
                {
                    "type": "response.output_text.delta",
                    "item_id": ident,
                    "output_index": index,
                    "content_index": 0,
                    "delta": item.value,
                }
            )
        elif isinstance(item, Code):
            value = {
                "id": ident,
                "type": "custom_tool_call",
                "call_id": item.call_id,
                "name": "exec",
                "namespace": "functions",
                "input": item.value,
            }
            frames.append(
                {
                    "type": "response.output_item.added",
                    "output_index": index,
                    "item": value,
                }
            )
        else:
            value = {
                "id": ident,
                "type": "function_call",
                "call_id": item.call_id,
                "name": item.name,
                "arguments": json.dumps(item.arguments),
            }
            frames.append(
                {
                    "type": "response.output_item.added",
                    "output_index": index,
                    "item": value,
                }
            )
        output.append(value)
        frames.append(
            {"type": "response.output_item.done", "output_index": index, "item": value}
        )
    frames.append({"type": "response.completed", "response": response})
    return frames


def messages(items, number, model):
    content = [
        {"type": "text", "text": item.value}
        if isinstance(item, Text)
        else {
            "type": "tool_use",
            "id": item.call_id,
            "name": item.name,
            "input": item.arguments,
        }
        for item in items
    ]
    stop = "tool_use" if any(isinstance(item, Call) for item in items) else "end_turn"
    message = {
        "id": f"msg_fixture_{number}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }
    frames = [
        {
            "type": "message_start",
            "message": {**message, "content": [], "stop_reason": None},
        }
    ]
    for index, item in enumerate(content):
        text = item["type"] == "text"
        frames += [
            {
                "type": "content_block_start",
                "index": index,
                "content_block": {**item, "text": ""}
                if text
                else {**item, "input": {}},
            },
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "text_delta", "text": item["text"]}
                if text
                else {
                    "type": "input_json_delta",
                    "partial_json": json.dumps(item["input"]),
                },
            },
            {"type": "content_block_stop", "index": index},
        ]
    frames += [
        {
            "type": "message_delta",
            "delta": {"stop_reason": stop, "stop_sequence": None},
            "usage": {"output_tokens": 20},
        },
        {"type": "message_stop"},
    ]
    return frames, message


class AnthropicFixtureProxy:
    """Authenticated first-party TLS fixture, streaming only to local inference.

    This replaces the user's upstream network for tests. It does not implement
    managed mediation, approvals, native hooks, or a production routing policy.
    """

    def __init__(self, provider, cert, key):
        self.provider = provider
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.capability = secrets.token_hex(32)
        self.authorization = (
            "Basic "
            + base64.b64encode(("fixture:" + self.capability).encode()).decode()
        )
        self.requests, self.denied, self.errors = [], [], []
        self.authenticated_connects = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.daemon_threads = True
        self.thread = Thread(
            target=self.server.serve_forever, name="native-fixture-proxy", daemon=True
        )
        self.thread.start()

    @property
    def url(self):
        return f"http://fixture:{self.capability}@127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        assert not self.thread.is_alive()

    def handler(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self):
                if self.headers.get("Proxy-Authorization") != owner.authorization:
                    return self.reply(
                        407, b'{"error":"fixture proxy authentication required"}'
                    )
                if self.path != "api.anthropic.com:443":
                    owner.denied.append({"method": "CONNECT", "path": self.path})
                    return self.reply(
                        403, b'{"error":"external fixture destination denied"}'
                    )
                owner.authenticated_connects += 1
                self.send_response(200, "Connection established")
                self.end_headers()
                self.wfile.flush()
                try:
                    self.connection = owner.context.wrap_socket(
                        self.connection, server_side=True
                    )
                    self.rfile, self.wfile = (
                        self.connection.makefile("rb"),
                        self.connection.makefile("wb"),
                    )
                    self.close_connection = False
                except ssl.SSLError as exc:
                    owner.errors.append(type(exc).__name__)
                    self.close_connection = True

            def do_GET(self):
                owner.denied.append({"method": "GET", "path": self.path})
                self.reply(404, b'{"error":"synthetic ancillary endpoint unavailable"}')

            def do_POST(self):
                path = urlsplit(self.path)
                if (
                    path.scheme
                    or path.netloc
                    or path.path not in ("/v1/messages", "/v1/messages/count_tokens")
                ):
                    owner.denied.append({"method": "POST", "path": self.path})
                    return self.reply(403, b'{"error":"unexpected fixture endpoint"}')
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1 << 20:
                    return self.reply(413, b"{}")
                token = TOKENS["claude"]
                credential_ok = (
                    self.headers.get("x-api-key") == token
                    or self.headers.get("Authorization") == "Bearer " + token
                )
                owner.requests.append(
                    {"path": self.path, "synthetic_credential": credential_ok}
                )
                if not credential_ok:
                    return self.reply(
                        403, b'{"error":"non-fixture credential rejected"}'
                    )
                data = self.rfile.read(length)
                headers = {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower()
                    not in (
                        "connection",
                        "proxy-authorization",
                        "proxy-connection",
                        "content-length",
                        "transfer-encoding",
                    )
                }
                try:
                    with httpx.Client(trust_env=False, timeout=20) as client:
                        with client.stream(
                            "POST",
                            owner.provider.base_url + self.path,
                            content=data,
                            headers=headers,
                        ) as response:
                            self.send_response(response.status_code)
                            for name in ("Content-Type", "Content-Length"):
                                if name in response.headers:
                                    self.send_header(name, response.headers[name])
                            self.end_headers()
                            for chunk in response.iter_raw():
                                self.wfile.write(chunk)
                                self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except BaseException as exc:
                    owner.errors.append(type(exc).__name__)
                    self.close_connection = True

        return Handler
