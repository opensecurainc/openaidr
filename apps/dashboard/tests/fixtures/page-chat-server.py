"""Real tenant API and PostgreSQL; the external Intelligence service is simulated."""

import asyncio
import json
import os
from pathlib import Path
import runpy
import signal
import sys
import time
from unittest.mock import patch
from uuid import uuid4

verify_runtime = runpy.run_path(str(Path(__file__).with_name("browser-runtime.py")))["prepare"]()

import httpx
import psycopg
from psycopg.conninfo import make_conninfo
import uvicorn

from openaidr.server.app import create_app
from openaidr.server.auth import hash_password
from openaidr.server.config import Config
from openaidr.server.store import Store

pending = {}
MARKDOWN_QUESTION = "Summarize the **visible activity**."
MARKDOWN_ANSWER = """### Summary

**7 open alerts** need review.

- **5 high** severity alerts
- **2 medium** severity alerts

```sh
openaidr-server --help
# /var/log/openaidr/2026/10/02/retained-telemetry-exports/session-events.log
```

| Status | Count | Source |
| --- | ---: | --- |
| Open | 7 | /var/log/openaidr/2026/10/02/retained-telemetry-exports/session-events.log |
| Closed | 3 | server.log |

1. Review *high* severity alerts first.
2. Check the `server.log` entry.

> Based only on the current page.
"""


class ServiceStream(httpx.AsyncByteStream):
    def __init__(self, question, result):
        self.question = question
        self.result = result
        self.gate = asyncio.Event()
        if question in ("Summarize the visible alerts.", "simulate slow reply", "simulate interrupted reply", MARKDOWN_QUESTION):
            pending[question] = self
        else:
            self.gate.set()

    async def __aiter__(self):
        if self.result.json()["status"] == "error":
            yield ("data: " + json.dumps(self.result.json()) + "\n\n").encode()
            return
        answer = self.result.json()["result"]["answer"]
        split = answer.index("\n```\n") if self.question == MARKDOWN_QUESTION else 14
        for index, delta in enumerate((answer[:split], answer[split:])):
            if index:
                await self.gate.wait()
                if self.question == "simulate interrupted reply":
                    return
            event = {"type": "delta", "text": delta}
            yield ("data: " + json.dumps(event) + "\n\n").encode()
        yield ("data: " + json.dumps(self.result.json()) + "\n\n").encode()

    async def aclose(self):
        if pending.get(self.question) is self:
            del pending[self.question]


async def async_upstream(transport, request):
    payload = json.loads(request.content)
    result = upstream(transport, request)
    if result.status_code != 200 or not payload.get("stream"):
        return result
    return httpx.Response(200, stream=ServiceStream(payload["messages"][-1]["content"], result),
                          headers={"content-type": "text/event-stream"})


def upstream(_transport, request):
    assert str(request.url) == "https://intelligence.example.test/v1/services/assistant/respond"
    assert request.headers["authorization"].startswith("Bearer oasc_")
    payload = json.loads(request.content)
    assert set(payload) in ({"page", "messages", "stream", "timeout_ms"}, {"page", "messages", "timeout_ms"})
    question = payload["messages"][-1]["content"]
    page = payload["page"]
    receipt = {"request_id": request.headers["idempotency-key"], "service": "assistant", "state": "disabled",
               "credits_reserved": None, "credits_charged": None, "rate_version": None}
    if question == "simulate failure":
        return httpx.Response(200, json={"status": "error", "code": "provider_unavailable",
                                        "retry_after": None, "profile": "assistant.1", "billing": receipt})
    if question == "simulate slow reply" and not payload.get("stream"):
        time.sleep(2)
    answer = "Visible page: " + page["title"] + "."
    if question.startswith("Repeat this identifier: "):
        answer = question.removeprefix("Repeat this identifier: ")
    if question == MARKDOWN_QUESTION:
        answer = MARKDOWN_ANSWER
    if question == "simulate markup":
        answer = """<img src="https://example.invalid/tracker-html" onerror="alert(1)">

<script>alert(1)</script>

![Image description](https://example.invalid/tracker-markdown)

[Unsafe script](javascript:alert%281%29)
[Unsafe encoded script](jav&#x61;script:alert%281%29)
[Unsafe data](data:text/html;base64,PHNjcmlwdD4=)
[Unsafe file](file:///etc/passwd)
[Safe link](https://example.invalid/details)
"""
    value = {"status": "completed", "result": {"answer": answer}, "profile": "assistant.1", "billing": receipt}
    return httpx.Response(200, json=value)


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    url = os.environ["OPENAIDR_TEST_DATABASE_URL"]
    schema = "page_chat_browser_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    try:
        st.migrate()
        tenant = st.bootstrap_tenant("Page chat test", "page-chat-test")["tenant"]
        st.create_user(
            tenant["id"],
            "viewer@chat.example.invalid",
            "Test viewer",
            hash_password("page-chat-test-password"),
            "viewer",
        )
        cfg = Config(
            database_url=st.url,
            public_url=os.environ.get("OPENAIDR_DEMO_URL", "http://127.0.0.1:3000"),
            tenant_id=tenant["id"], intelligence_origin="https://intelligence.example.test",
            intelligence_api_key="oasc_" + "a" * 32 + "." + "b" * 43,
        )
        cfg.set_services("api")
        app = create_app(cfg, st, customer=True)

        @app.get("/__test__/streams")
        async def streams():
            return {"pending": list(pending)}

        @app.post("/__test__/streams/release")
        async def release_streams():
            for stream in pending.values():
                stream.gate.set()
            return {}

        @app.post("/__test__/reset-admission")
        async def reset_admission():
            assert not pending
            chat = app.state.service.page_chat
            with chat._lock:
                chat._attempts.clear()
            return {}

        # Test controls must precede the application's catch-all route.
        app.router.routes[:] = app.router.routes[-3:] + app.router.routes[:-3]

        with patch.object(httpx.HTTPTransport, "handle_request", upstream), patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", async_upstream,
        ):
            uvicorn.run(
                app,
                host="127.0.0.1",
                port=int(os.environ.get("OPENAIDR_CHAT_TEST_API_PORT", "8773")),
                log_level="warning",
            )
    finally:
        st.close()
        with psycopg.connect(url, autocommit=True) as connection:
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


if __name__ == "__main__":
    try:
        main()
    finally:
        verify_runtime()
