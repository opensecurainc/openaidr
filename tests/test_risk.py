import asyncio
import copy
import gzip
import json
import time
from unittest.mock import Mock

import httpx
import pytest

from openaidr.server.config import from_env
from openaidr.server.detect_constants import RULES
from openaidr.server.model_costs import parse_usage
from openaidr_api.providers.guardrail import CATEGORY_CRITERIA, JevClient, parse_assessment
from openaidr.server.guardrail.scoring import (
    ACTIVITY_LABELS,
    DETECTION_RULE_ID,
    KINDS,
    MAX_STATE_BYTES,
    JevError,
    RiskWorker,
    assessment_state,
    detection_finding,
    event_evidence,
)


def reply(category="secret_exfiltration", score=3.2):
    return {
        "model": "jev-1.13.0",
        "answers": {
            "category": {"type": "choice", "choice": category, "confidence": 0.9},
            "severity": {"type": "score", "score": score, "confidence": 0.8},
        },
    }


@pytest.mark.parametrize("counts", [None, {}, [], {"input_tokens": 10}, {"input_tokens": True, "output_tokens": 0}, {"input_tokens": -1, "output_tokens": 0}, {"input_tokens": 1.5, "output_tokens": 0}, {"input_tokens": "20", "output_tokens": 0}, {"input_tokens": 2**53, "output_tokens": 0}])
def test_missing_or_malformed_model_usage_stays_unknown(counts):
    usage = parse_usage({"model": "jev-1.13.0", "usage": counts})
    assert usage == {"model": "jev-1.13.0", "input_tokens": None, "output_tokens": None}
    assert parse_usage({"usage": {"input_tokens": 0, "output_tokens": 0}}) == {
        "model": None, "input_tokens": 0, "output_tokens": 0,
    }


def test_scores_are_severity_not_confidence():
    result = parse_assessment(reply())
    assert result["score"] == 80
    assert result["confidence"] == 0.8
    assert result["category_confidence"] == 0.9
    assert result["level"] == "critical"
    assert result["category"] == "secret_exfiltration"
    assert result["model"] == "jev-1.13.0"
    assert result["rubric_version"] == 1
    assert len(CATEGORY_CRITERIA) == 8
    safe = parse_assessment(reply("none", 0))
    assert safe["score"] == 0 and safe["category"] == "none"


@pytest.mark.parametrize("category", ["unknown", "none"])
def test_unknown_or_inconsistent_answers_never_become_safe(category):
    result = parse_assessment(reply(category, 3))
    assert result["status"] == "unscored"
    assert result["score"] is None
    assert result["category"] == "unknown"


@pytest.mark.parametrize("severity", [0, 0.001])
def test_risk_category_with_displayed_zero_severity_remains_unscored(severity):
    result = parse_assessment(reply("secret_exfiltration", severity))
    assert result["status"] == "unscored" and result["score"] is None
    assert result["category"] == "unknown" and result["level"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("score", -1),
        ("score", 4.1),
        ("score", float("nan")),
        ("score", float("inf")),
        pytest.param("score", 10 ** 1000, id="overflowing-integer"),
        ("score", "3"),
        ("score", True),
        ("confidence", 1.1),
        ("confidence", None),
        ("type", "noul"),
    ],
)
def test_rejects_malformed_scores(field, value):
    payload = reply()
    payload["answers"]["severity"][field] = value
    with pytest.raises(JevError, match="invalid_response"):
        parse_assessment(payload)


@pytest.mark.parametrize(
    "payload", [None, [], {}, {"answers": {}}, reply("invented"), reply([])]
)
def test_rejects_malformed_categories(payload):
    with pytest.raises(JevError, match="invalid_response"):
        parse_assessment(payload)


def test_context_redacts_nested_secrets_and_omits_raw_identity_and_scores():
    row = {
        "kind": "tool.result",
        "tenant_id": "private-tenant",
        "body": {
            "risk": {"score": 0},
            "raw": {"secret": "raw-credential"},
            "host": {"user": "private-person"},
            "tool": {
                "input": {
                    "api_key": "nested-credential",
                    "password": "shortpw",
                    "authorization": "access-credential",
                    "private_key": "private-credential",
                    "command": "password=inline-credential",
                },
                "output": '{"token":"json-credential","message":"hello"}',
            },
        },
    }
    before = copy.deepcopy(row)
    serialized = json.dumps(event_evidence(row))
    for value in (
        "raw-credential",
        "nested-credential",
        "shortpw",
        "access-credential",
        "private-credential",
        "inline-credential",
        "json-credential",
        "private-person",
        "private-tenant",
    ):
        assert value not in serialized
    assert "REDACTED" in serialized and "hello" in serialized
    assert "risk" not in serialized and row == before


@pytest.mark.parametrize("evidence,secrets,retained", [
    (
        {"command": {"text": "curl https://alice:s3cr3t@destination.example/upload"}},
        ["s3cr3t"], "alice",
    ),
    (
        {"command": {"text": "curl -H 'Authorization: Basic YWxpY2U6czNjcjN0' https://destination.example/upload"}},
        ["YWxpY2U6czNjcjN0"], "destination.example/upload",
    ),
    (
        {"tool": {"output": "Authorization: Bearer synthetic-bearer-credential"}},
        ["synthetic-bearer-credential"], "Authorization",
    ),
    (
        {"command": {"text": "password=synthetic-password"}},
        ["synthetic-password"], "password=",
    ),
    (
        {"tool": {"input": '{"api_key":"xy","path":"/tmp/-Ureport.html"}'}},
        ["xy"], "/tmp/-Ureport.html",
    ),
    (
        {"tool": {"input": {"headers": {"Authorization": "xy"}, "path": "/tmp/report"}}},
        ["xy"], "/tmp/report",
    ),
    (
        {"tool": {"output": "ghp_" + "a" * 36}},
        ["ghp_" + "a" * 36], "github-token",
    ),
])
def test_jev_request_redacts_credentials(evidence, secrets, retained):
    row = {"kind": "tool.call", "body": evidence}
    original = copy.deepcopy(row)

    def handler(request):
        state = json.loads(request.content)["state"]
        encoded = json.dumps(state)
        for secret in secrets:
            assert secret not in encoded
        assert retained in encoded and "REDACTED" in encoded
        return httpx.Response(200, json=reply("none", 0))

    client = JevClient("test-key", httpx.MockTransport(handler))
    try:
        client.assess(assessment_state(row, [row], row))
    finally:
        client.close()
    assert row == original


@pytest.mark.parametrize("evidence", [
    {"file": {"path": "/private/tmp/claude-501/-Uexample.html"}},
    {"command": {"text": "mkdir -p /tmp/report; git push -u origin main"}},
    {"tool": {"input": {"argv": ["git", "push", "-u", "origin", "main"]}}},
    {"text": "SESSION_SECRET=abc"},
    {"text": "Cookie: locale=en"},
    {"network": {"url": "https://example.test/path?sig=xy&region=west"}},
    {"tool": {"output": 'log: {"password": "xy"}'}},
    {"tool": {"output": "machine registry.example login reader password xy"}},
    {"text": "2026-10-20T15:42:38+00:00 through 2026-10-20T16:42:38+00:00"},
    {"tool": {"output": "db:5432:app:reader:xy"}},
    {"tool": {"output": "client-key-data: YWJj"}},
    {"tool": {"output": "_auth=YWJj"}},
    {"tool": {"output": "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nYWJj\nPrivate-MAC: example"}},
    {"tool": {"output": 'Captured {"sensitive":true,"value":"example"}'}},
    {"network": {"url": "//reader@example.test/path"}},
    {"tool": {"output": "<settings><password>xy</password></settings>"}},
    {"tool": {"output": "<![invalid]>"}},
    {"tool": {"input": {"headers": [["Cookie", "locale=en"]]}}},
    {"tool": {"output": {"type": "random_password", "values": {"result": "example"}}}},
])
def test_provider_preserves_evidence_without_backend_heuristics(evidence):
    row = {"kind": "tool.call", "body": evidence}
    original = copy.deepcopy(row)

    def handler(request):
        state = json.loads(request.content)["state"]
        expected = {"kind": "tool.call", **evidence}
        assert state["target_event"] == expected
        assert state["latest_prompt"] == expected
        assert state["prior_events"] == [expected]
        return httpx.Response(200, json=reply("none", 0))

    client = JevClient("test-key", httpx.MockTransport(handler))
    try:
        client.assess(assessment_state(row, [row], row))
    finally:
        client.close()
    assert row == original


def test_noncredential_urls_and_text_keep_their_evidence():
    body = {
        "text": "Discuss cookie handling and HTTP authorization schemes.",
        "network": {"url": "https://destination.example/path?contact=alice@example.com"},
        "command": {"text": "docker login --password-stdin registry.example; vendorctl --token-file ./token.txt --no-password --region west"},
        "tool": {"input": {
            "headers": [{"name": "Accept", "values": ["application/json"]}],
            "items": ["Discuss token handling", "Retain the next item"],
            "topic": {"name": "Review cookie handling", "description": "Keep this evidence"},
            "terraform": {"type": "aws_instance", "name": "web", "values": {"id": "i-example"}, "sensitive_values": {}},
            "openssl": "openssl pkcs12 -in cert.p12 -out cert.pem -nokeys",
        }, "output": 'INFO:worker:request:completed:ready\n# hostname:port:database:username:password\n<settings><password/><id>public-repository</id><add key="region" value="west"/></settings>'},
    }
    assert event_evidence({"kind": "prompt", "body": body}) == {"kind": "prompt", **body}


@pytest.mark.parametrize("character", ["界", '"', "\\", "\n"])
def test_private_key_redaction_does_not_break_json_and_context_is_bounded(character):
    row = {
        "kind": "response",
        "body": {"text": "-----BEGIN PRIVATE KEY-----\nprivate-content\n"},
    }
    assert "private-content" not in json.dumps(event_evidence(row))
    huge = {"kind": "prompt", "body": {"text": character * 30_000}}
    state = assessment_state(huge, [huge] * 12, huge)
    assert state["target_event"]["truncated"]
    assert len(json.dumps(state, ensure_ascii=False).encode()) <= MAX_STATE_BYTES
    assert state["context_limited"]


@pytest.mark.parametrize("size", [20, 7950])
def test_latest_prompt_is_not_duplicated_or_displacing_distinct_context(size):
    prompt = {"id": "prompt", "kind": "prompt", "body": {"text": "p" * size}}
    target = {"id": "target", "kind": "response", "body": {"text": "r" * size}}
    earlier = {"id": "earlier", "kind": "tool.result", "body": {"text": "Earlier evidence"}}
    state = assessment_state(target, [earlier, copy.deepcopy(prompt)], prompt)
    assert state["latest_prompt"] == event_evidence(prompt)
    assert state["prior_events"] == [event_evidence(earlier)]
    assert len(json.dumps(state, ensure_ascii=False).encode()) <= MAX_STATE_BYTES


def test_client_uses_only_official_endpoint_and_structured_questions():
    def handler(request):
        assert str(request.url) == "https://api.typesafe.ai/v1/systemone"
        assert request.headers["authorization"] == "Bearer test-key"
        assert request.headers["accept-encoding"] == "identity"
        data = json.loads(request.content)
        assert data["model"] == "jev-1.13.0"
        assert data["state"] == {"target_event": "test"}
        assert set(data["questions"]) == {"category", "severity"}
        return httpx.Response(200, json=reply())

    client = JevClient("test-key", httpx.MockTransport(handler))
    try:
        assert client.assess({"target_event": "test"})["score"] == 80
    finally:
        client.close()


@pytest.mark.parametrize(
    "status,retryable",
    [(401, True), (403, True), (408, True), (422, False), (302, False), (429, True), (529, True), (503, True)],
)
def test_provider_errors_never_expose_body(status, retryable):
    client = JevClient(
        "test-key",
        httpx.MockTransport(lambda r: httpx.Response(status, text="private-evidence")),
    )
    try:
        with pytest.raises(JevError) as exc:
            client.assess({})
        assert exc.value.retryable == retryable
        assert "private-evidence" not in str(exc.value)
    finally:
        client.close()


def test_timeout_is_retryable_and_malformed_json_is_not():
    def timeout(request):
        raise httpx.ReadTimeout("private-evidence")

    for handler, retry in (
        (timeout, True),
        (lambda r: httpx.Response(200, text="not json"), False),
    ):
        client = JevClient("test-key", httpx.MockTransport(handler))
        try:
            with pytest.raises(JevError) as exc:
                client.assess({})
            assert exc.value.retryable == retry
        finally:
            client.close()


class ProviderStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0):
        self.chunks, self.delay = chunks, delay
        self.bytes_read = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            time.sleep(self.delay)
            self.bytes_read += len(chunk)
            yield chunk

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.bytes_read += len(chunk)
            yield chunk

    def close(self):
        self.closed = True

    async def aclose(self):
        self.close()


def test_valid_streamed_response_at_the_size_limit():
    body = json.dumps(reply()).encode()
    body += b" " * (64_000 - len(body))
    stream = ProviderStream([body[i:i + 1024] for i in range(0, len(body), 1024)])
    client = JevClient(
        "test-key", httpx.MockTransport(lambda r: httpx.Response(200, stream=stream))
    )
    try:
        assert client.assess({})["score"] == 80
        assert stream.bytes_read == len(body) and stream.closed
    finally:
        client.close()
        client.close()


@pytest.mark.parametrize("content_length", [False, True])
def test_provider_response_is_bounded_while_streaming(content_length):
    chunks = [json.dumps(reply()).encode()] + [b" " * 4096] * 64
    stream = ProviderStream(chunks)
    headers = {"content-length": str(sum(map(len, chunks)))} if content_length else {}
    client = JevClient(
        "test-key",
        httpx.MockTransport(lambda r: httpx.Response(200, headers=headers, stream=stream)),
    )
    try:
        with pytest.raises(JevError, match="response_too_large") as exc:
            client.assess({})
        assert not exc.value.retryable
        assert stream.bytes_read <= 64_000 + 4096
        assert stream.closed
    finally:
        client.close()


def test_provider_cannot_bypass_response_cap_with_compression():
    stream = ProviderStream([gzip.compress(json.dumps(reply()).encode() + b" " * 1_000_000)])
    client = JevClient(
        "test-key",
        httpx.MockTransport(lambda r: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)),
    )
    try:
        with pytest.raises(JevError, match="invalid_response"):
            client.assess({})
        assert stream.bytes_read == 0 and stream.closed
    finally:
        client.close()


def test_provider_error_status_does_not_read_the_body():
    stream = ProviderStream([b"private-evidence"] * 100)
    client = JevClient(
        "test-key",
        httpx.MockTransport(lambda r: httpx.Response(408, stream=stream)),
    )
    try:
        with pytest.raises(JevError, match="provider_unavailable") as exc:
            client.assess({})
        assert exc.value.retryable
        assert stream.bytes_read == 0 and stream.closed
    finally:
        client.close()


def test_provider_total_deadline_cancels_a_trickling_response(monkeypatch):
    from openaidr_api.providers import guardrail as risk

    monkeypatch.setattr(risk, "REQUEST_TIMEOUT", 0.05, raising=False)
    stream = ProviderStream([json.dumps(reply()).encode()] + [b" "] * 100, delay=0.01)
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=stream) if calls == 1 else httpx.Response(200, json=reply())

    client = JevClient("test-key", httpx.MockTransport(handler))
    try:
        start = time.monotonic()
        with pytest.raises(JevError, match="connection_failed") as exc:
            client.assess({})
        assert exc.value.retryable
        assert time.monotonic() - start < 0.5
        assert stream.bytes_read < sum(map(len, stream.chunks)) and stream.closed
        assert client.assess({})["score"] == 80
    finally:
        client.close()


def test_provider_total_deadline_includes_response_headers(monkeypatch):
    from openaidr_api.providers import guardrail as risk

    monkeypatch.setattr(risk, "REQUEST_TIMEOUT", 0.05, raising=False)

    class DelayedTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
        def handle_request(self, request):
            time.sleep(1)
            return httpx.Response(200, json=reply())

        async def handle_async_request(self, request):
            await asyncio.sleep(1)
            return httpx.Response(200, json=reply())

    client = JevClient("test-key", DelayedTransport())
    try:
        start = time.monotonic()
        with pytest.raises(JevError, match="connection_failed") as exc:
            client.assess({})
        assert exc.value.retryable
        assert time.monotonic() - start < 0.5
    finally:
        client.close()


def test_worker_keeps_errors_unscored_and_skips_empty_queue():
    st, client = Mock(), Mock()
    st.many.return_value = []
    row = {"id": "event", "tenant_id": "tenant", "kind": "prompt", "body": {"text": "hi"}, "risk_attempts": 1, "risk_retry_attempts": 1}
    st.claim_risk_event.return_value = row
    st.risk_context.return_value = ([], None)
    st.risk_knowledge.return_value = {"enabled": False, "documents": []}
    client.assess.side_effect = JevError("connection_failed", retryable=True)
    worker = RiskWorker(st, client, "tenant")
    assert worker.tick()
    st.claim_risk_event.assert_called_once_with(
        "tenant"
    )
    st.finish_risk_event.assert_called_once_with(
        row, {"status": "error", "reason": "connection_failed", "knowledge": st.risk_knowledge.return_value},
        30, provider_delay=30
    )
    st.risk_knowledge.side_effect = RuntimeError("lookup unavailable")
    client.reset_mock()
    worker.retry_at = 0
    assert worker.tick()
    client.assess.assert_not_called()
    st.finish_risk_event.assert_called_with(
        row, {"status": "error", "reason": "assessment_failed"}, True, provider_delay=0,
    )
    client.reset_mock()
    st.claim_risk_event.return_value = None
    worker.retry_at = 0
    assert not worker.tick()
    client.assess.assert_not_called()


def test_provider_retry_after_defers_the_whole_worker():
    from openaidr_api.providers.guardrail import retry_delay

    assert retry_delay("120") == 120
    assert retry_delay("invalid") == 30
    st, client = Mock(), Mock()
    st.many.return_value = []
    st.claim_risk_event.return_value = {"id": "x", "tenant_id": "tenant", "kind": "prompt", "risk_attempts": 1, "risk_retry_attempts": 1}
    st.risk_context.return_value = ([], None)
    st.risk_knowledge.return_value = {"enabled": False, "documents": []}
    client.assess.side_effect = JevError("provider_unavailable", True, 120)
    worker = RiskWorker(st, client)
    assert worker.tick()
    assert not worker.tick()
    st.claim_risk_event.assert_called_once()
    assert st.finish_risk_event.call_args.args[-1] == 120


@pytest.mark.parametrize(
    "retry_after",
    ["1000000000000", "9" * 500, "Fri, 31 Dec 9999 23:59:59 GMT"],
    ids=["large-number", "overflowing-number", "distant-date"],
)
def test_provider_retry_delays_are_bounded_before_scheduling(retry_after):
    import time

    st = Mock()
    st.many.return_value = []
    st.claim_risk_event.return_value = {"id": "x", "tenant_id": "tenant", "kind": "prompt", "risk_attempts": 1, "risk_retry_attempts": 1}
    st.risk_context.return_value = ([], None)
    st.risk_knowledge.return_value = {"enabled": False, "documents": []}
    client = JevClient(
        "test-key",
        httpx.MockTransport(
            lambda r: httpx.Response(429, headers={"Retry-After": retry_after})
        ),
    )
    try:
        worker = RiskWorker(st, client)
        assert worker.tick()
        assert 0 < worker.retry_at - time.monotonic() <= 3600
        assert st.finish_risk_event.call_args.args[-1] == 3600
        assert st.finish_risk_event.call_args.kwargs["provider_delay"] == 3600
    finally:
        client.close()


def test_tenant_ignores_direct_guardrail_key_environment(monkeypatch):
    for name in ("OPENAIDR_JEV_API_KEY", "OPENAIDR_JEV_API_KEY_FILE", "TYPESAFE_API_KEY"):
        monkeypatch.setenv(name, "private-provider-key")
    assert "private-provider-key" not in repr(from_env())
    assert not hasattr(from_env(), "jev_api_key")


def activity_row(kind, **updates):
    row = {
        "id": "event",
        "tenant_id": "tenant",
        "sensor_id": "sensor",
        "agent_id": "agent",
        "session_id": "session",
        "time": "2026-09-30T17:00:00+00:00",
        "kind": kind,
        "product": "claude-code",
        "body": {
            "host": {"hostname": "host", "os": "macos", "user": "alice"},
            "agent": {"product": "claude-code", "account": "dev@example.com"},
        },
    }
    row.update(updates)
    return row


@pytest.mark.parametrize(
    "kind,activity",
    [
        ("prompt", "prompt"),
        ("tool.call", "tool call"),
        ("tool.result", "tool result"),
        ("command", "tool call"),
    ],
)
def test_material_assessments_of_agent_activity_create_detections(kind, activity):
    finding = detection_finding(activity_row(kind), parse_assessment(reply()))
    assert finding["rule_id"] == DETECTION_RULE_ID
    assert finding["category"] == "secret_exfiltration"
    assert finding["severity"] == "critical"
    assert finding["title"] == f"Secret exfiltration risk in a {activity}"
    assert finding["summary"] == (
        f"The Jev model assessed this {activity} as secret exfiltration at "
        "critical severity (80/100, severity confidence 0.8, category "
        "confidence 0.9)."
    )
    assert finding["tenant_id"] == "tenant" and finding["sensor_id"] == "sensor"
    assert finding["agent_id"] == "agent" and finding["session_id"] == "session"
    assert finding["host"] == {"hostname": "host", "os": "macos", "user": "alice"}
    assert finding["product"] == "claude-code"
    assert finding["account"] == "dev@example.com"
    assert finding["event_ids"] == ["event"]
    assert finding["primary_event_id"] == "event"
    assert finding["first_event_at"] == "2026-09-30T17:00:00+00:00"


@pytest.mark.parametrize(
    "kind,assessment",
    [
        ("response", parse_assessment(reply())),
        ("session.start", parse_assessment(reply())),
        ("tool.call", parse_assessment(reply("unknown", 3.2))),
        ("tool.call", {"status": "error", "reason": "provider_unavailable"}),
    ],
    ids=["response", "session-event", "unscored", "provider-error"],
)
def test_advisory_assessments_never_create_detections(kind, assessment):
    assert detection_finding(activity_row(kind), assessment) is None


def test_detection_rule_is_registered_for_the_detection_kinds():
    rule = next(rule for rule in RULES if rule["id"] == DETECTION_RULE_ID)
    assert rule["name"] == "Jev risk detection"
    assert set(ACTIVITY_LABELS) <= set(KINDS)
