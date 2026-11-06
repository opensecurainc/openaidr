"""Tenant-owned provider fixtures for the separately installed API service.

Retained from the pre-extraction service tests at df0a0004. These helpers are
synthetic test inputs; runtime requests still pass through the real service.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import time
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from openaidr_api import skills
from openaidr_api.app import Config, create_app
from openaidr_api.threat_intel import keys
from openaidr_api_client.contracts import guardrail as scoring, investigations as wire
from openaidr_api_client.contracts.skills import TASKS
from openaidr_api_client.validation import page_chat



BAD = "https://malware.example.com/download"


def contract_validator(document, schema):
    # Keep local component references rooted in the published OpenAPI document.
    return Draft202012Validator({"components": document["components"], **schema},
                                format_checker=FormatChecker())


def assert_response_contract(app, result):
    document = app.openapi()
    path = result.request.url.path
    if result.request.method == "GET" and path in ("/docs", "/openapi.json"):
        assert result.status_code == 200
        if path == "/docs":
            assert result.headers["content-type"] == "text/html; charset=utf-8"
            assert "SwaggerUIBundle" in result.text and "/openapi.json" in result.text
        else:
            assert result.headers["content-type"] == "application/json"
            assert result.json() == document
        return result
    if path not in document["paths"]:
        path = next((candidate for candidate in document["paths"]
                     if re.fullmatch(re.escape(candidate).replace(r"\{id\}", "[^/]+"), path)), None)
        if path is None:
            assert result.status_code == 404
            return result
    operation = document["paths"][path][result.request.method.lower()]
    assert str(result.status_code) in operation["responses"]
    schema = operation["responses"][str(result.status_code)]["content"]["application/json"]["schema"]
    assert result.headers["content-type"] == "application/json"
    assert result.headers["cache-control"] == "no-store"
    contract_validator(document, schema).validate(result.json())
    return result


class ContractClient(TestClient):
    def request(self, *args, **kwargs):
        return assert_response_contract(self.app, super().request(*args, **kwargs))


class ThreatProvider:
    def __init__(self):
        self.requests, self.failed = [], False
        self.expiry = time.time() + 300

    def handle(self, request):
        self.requests.append(request)
        if self.failed:
            return httpx.Response(503, text="private upstream error")
        if request.url.host == "webrisk.googleapis.com":
            return httpx.Response(200, json={"threat": {"threatTypes": ["MALWARE"],
                "expireTime": datetime.fromtimestamp(self.expiry, timezone.utc).isoformat()}}
                if request.url.params["uri"] == BAD else {})
        assert request.url.host == "api.osv.dev"
        if request.url.path == "/v1/querybatch":
            query = json.loads(request.content)["queries"][0]
            name = query["package"]["name"]
            if name == "broken":
                return httpx.Response(200, json={"invalid": True})
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-example"}]} if name == "example" else {}]})
        assert request.url.path == "/v1/vulns/GHSA-example"
        return httpx.Response(200, json={"id": "GHSA-example", "aliases": ["CVE-2026-1234"],
            "summary": "Example vulnerability", "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "example"},
                          "ranges": [{"type": "SEMVER", "events": [{"fixed": "2.0.0"}]}]}]})


def provider_answer(answer="Captured Jev evidence"):
    return {"status": "completed", "model": page_chat.MODEL, "service_tier": "default",
            "usage": {"input_tokens": 123, "output_tokens": 10, "input_tokens_details": {"cached_tokens": 0}},
            "output": [{"type": "message", "role": "assistant",
                        "content": [{"type": "output_text", "text": answer}]}]}


def overview_result(citation="one"):
    return {"items": [{"topic": "Findings", "headline": "0", "caption": "findings", "text": "No findings shown.",
                       "detail": "The supplied count is zero.", "tone": "neutral", "citations": [citation]}]}


def event(value):
    return ("data: " + json.dumps(value) + "\n\n").encode()


class ProviderStream(httpx.AsyncByteStream):
    def __init__(self, chunks, block=False):
        self.chunks, self.block, self.closed = chunks, block, False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk
        if self.block:
            await asyncio.Event().wait()

    async def aclose(self):
        self.closed = True


@pytest.fixture
def application_service(tmp_path):
    from test_application_classification import response as provider_response
    db = tmp_path / "keys.sqlite3"
    keys.initialize(db)
    tenant = str(uuid4())
    credentials = []
    for index in range(2):
        path = tmp_path / f"key-{index}"
        ident = keys.issue(db, tenant, path)
        credentials.append((ident, {"Authorization": "Bearer " + path.read_text().strip()}))
    provider = SimpleNamespace(requests=[], body=provider_response(), status=200, text=None, headers={}, error=None)

    def handle(request):
        assert str(request.url) == "https://api.openai.com/v1/responses"
        provider.requests.append(request)
        if provider.error:
            raise provider.error
        if provider.text is not None:
            return httpx.Response(provider.status, text=provider.text, headers=provider.headers)
        return httpx.Response(provider.status, json=provider.body, headers=provider.headers)

    transport = httpx.MockTransport(handle)
    config = Config(str(db), openai_key="private-service-openai-key")
    app = create_app(config, transport=transport, version="2026.10.27+1234567")
    with ContractClient(app) as client:
        yield SimpleNamespace(app=app, config=config, db=db, tenant=tenant, client=client,
                              provider=provider, credentials=credentials, transport=transport)
    assert not app.state.apps_admission.active


@pytest.fixture
def skill_service(tmp_path, monkeypatch):
    binary = Path(os.environ.get("OPENAIDR_TEST_SKILLSPECTOR_BINARY", "/opt/skillspector/bin/skillspector"))
    assert binary.is_file(), "Install the pinned scanner and set OPENAIDR_TEST_SKILLSPECTOR_BINARY"
    monkeypatch.setattr(skills, "RUNTIME_PYTHON", str(binary.with_name("python")))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-child")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://untrusted.invalid/")
    processes = []
    create_process = asyncio.create_subprocess_exec

    async def tracked_process(*args, **kwargs):
        assert set(kwargs["env"]) == {"PATH", "LANG", "PYTHONUTF8"}
        process = await create_process(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(skills.asyncio, "create_subprocess_exec", tracked_process)
    db = tmp_path / "keys.sqlite3"
    keys.initialize(db)
    key_file = tmp_path / "key"
    tenant = str(uuid4())
    identifier = keys.issue(db, tenant, key_file)
    headers = {"Authorization": "Bearer " + key_file.read_text().strip()}
    provider = SimpleNamespace(requests=[], invalid=False, unknown=False)

    def handle(request):
        assert str(request.url) == "https://api.openai.com/v1/chat/completions"
        provider.requests.append(request)
        payload = json.loads(request.content)
        schema = payload.get("response_format", {}).get("json_schema", {}).get("name", "")
        if payload.get("tools"):
            schema = payload["tools"][0]["function"]["name"]
        output = {"is_mismatch": False} if "TP4" in schema else {"findings": []}
        invalid = provider.invalid or (getattr(provider, "invalid_once", False) and len(provider.requests) == 1)
        text = "not JSON" if invalid else json.dumps(output)
        message = {"role": "assistant", "content": text}
        if payload.get("tools"):
            name = payload["tools"][0]["function"]["name"]
            message = {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_fixture", "type": "function", "function": {"name": name, "arguments": text}}]}
        reply = {"id": "chatcmpl-fixture", "object": "chat.completion", "created": 1,
                 "model": "gpt-6-luna", "service_tier": "default",
                 "choices": [{"index": 0, "message": message, "finish_reason": "stop"}]}
        if not provider.unknown:
            reply["usage"] = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120,
                              "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
        return httpx.Response(200, json=reply)

    provider.task = TASKS[0]
    transport = httpx.MockTransport(handle)
    app = create_app(Config(str(db), openai_key="private-service-openai-key"), transport=transport,
                     version="2026.10.27+1234567")
    with ContractClient(app) as client:
        yield SimpleNamespace(app=app, client=client, headers=headers, db=db, identifier=identifier,
                              provider=provider, transport=transport, tenant=tenant, processes=processes)
    assert not app.state.skills_admission.active
    assert all(process.returncode is not None for process in processes)


def answer(category="none", severity=0):
    return {"model": scoring.MODEL, "answers": {
        "category": {"type": "choice", "choice": category, "confidence": 0.9},
        "severity": {"type": "score", "score": severity, "confidence": 0.8},
    }, "usage": {"input_tokens": 123, "output_tokens": 0}}


class InvestigationProvider:
    def __init__(self, *, read=False):
        self.read = read
        self.counted, self.inferred, self.scored = [], [], []

    def handle(self, request):
        from test_session_investigator import no_finding

        body = json.loads(request.content)
        if request.url.host == "api.typesafe.ai":
            self.scored.append(body)
            return httpx.Response(200, json=answer("data_exfiltration", 4))
        assert request.url.host == "api.openai.com"
        assert request.headers["authorization"] == "Bearer synthetic-service-only-key"
        if request.url.path.endswith("/input_tokens"):
            self.counted.append(body)
            return httpx.Response(200, json={"object": "response.input_tokens", "input_tokens": 1000})
        assert request.url.path == "/v1/responses"
        assert all(body.get(key) == self.counted[-1].get(key) for key in
                   ("input", "tools", "text", "model", "instructions", "reasoning"))
        self.inferred.append(body)
        if self.read and len(self.inferred) == 1:
            item = dict(id="function-1", type="function_call", call_id="read-1", name="read_session",
                        arguments=json.dumps({"session_id": str(uuid4()), "snapshot_id": None, "cursor": ""}))
        else:
            item = dict(id="message-1", type="message", role="assistant", status="completed",
                        content=[dict(type="output_text", text=json.dumps(no_finding()), annotations=[])])
        value = dict(id="response-" + str(len(self.inferred)), object="response", status="completed",
                     model=wire.native.MODEL, service_tier="default", output=[item],
                     usage=dict(input_tokens=1000, output_tokens=20, total_tokens=1020,
                                input_tokens_details=dict(cached_tokens=0, cache_write_tokens=0),
                                output_tokens_details=dict(reasoning_tokens=0)))
        return httpx.Response(200, content=b"data: " + json.dumps({"type": "response.completed", "response": value}).encode() + b"\n\n",
                              headers={"content-type": "text/event-stream"})


def store_environment_key(st, cfg, origin, key):
    import json
    from cryptography.fernet import Fernet

    if not cfg.intelligence_keys_key:
        cfg.intelligence_keys_key = Fernet.generate_key().decode()
    encrypted = Fernet(cfg.intelligence_keys_key.encode()).encrypt(json.dumps([cfg.tenant_id, origin, key]).encode()).decode()
    st.execute("INSERT INTO tenant_intelligence_keys(tenant_id,origin,encrypted_api_key) VALUES($1,$2,$3)",
               cfg.tenant_id, origin, encrypted)
