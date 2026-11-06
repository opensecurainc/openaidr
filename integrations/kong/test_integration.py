#!/usr/bin/env python3
"""Exercise the packaged Kong plugin in a real, isolated container."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "kong:3.9.4"
TOKEN = "integration-only-gateway-credential"
SECRET_LABEL = "oagt_" + "s" * 43
CONSUMER = "0d6e1f4a-727c-4e10-a833-384da0e7af88"
SERVICE = "0d6e1f4a-727c-4e10-a833-384da0e7af89"
ROUTES = {name: str(uuid.uuid5(uuid.NAMESPACE_URL, "openaidr-test/" + name))
          for name in ("chat", "terminated", "ai", "classifier", "secret-labels", "unnamed")}


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def eventually(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for integration evidence")


def request(url, data=None, headers=None):
    encoded = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, encoded, headers or {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.read()


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # A timed-out Kong check deliberately closes its connection.

    def do_POST(self):
        state = self.server.state
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw)
        if self.path.startswith("/ingest/"):
            state["exports"].append(raw)
            if self.headers.get("Authorization") != "Bearer " + TOKEN:
                return self.reply(401, {"error": {"code": "unauthorized"}})
        if self.path.endswith("gateway-heartbeats"):
            state["heartbeats"].append(body)
            if state["heartbeat_failure"]:
                return self.reply(503, {})
            value = {"gateway_id": state["gateway_id"], "mode": state["mode"],
                     "capture_content": state["capture"], "version": 1, "enabled": True,
                     "guardrail_metrics": True}
            value.update(state["heartbeat_override"])
            return self.reply(200, value)
        if self.path.endswith("gateway-outcomes"):
            state["outcomes"].append(body)
            return self.reply(state["outcome_status"], {"accepted": True, "request_id": body["request_id"]})
        if self.path.endswith("gateway-checks"):
            state["checks"].append(body)
            identity = {"id": str(uuid.uuid4()), "request_id": body["request_id"]}
            if body["availability"] != "available":
                return self.reply(503, {**identity, "status": "unavailable", "error": {"code": "unavailable"}})
            behavior = state["behavior"]
            if behavior == "timeout":
                time.sleep(0.7)
            if behavior in ("unauthorized", "unavailable"):
                return self.reply(401 if behavior == "unauthorized" else 503, {})
            if behavior == "invalid_json":
                return self.reply(200, b"not json")
            if behavior == "oversized_response":
                return self.reply(200, b" " * 40000)
            value = {**identity, "status": "evaluated", "mode": state["mode"],
                     "settings_version": 1, "policy_version": 1, "reason": "Fixture rule",
                     "evaluated_decision": state["decision"],
                     "returned_decision": state["decision"] if state["mode"] == "enforce" else "allow"}
            if behavior == "mismatched_request":
                value["request_id"] = str(uuid.uuid4())
            if behavior == "invalid_shadow":
                value["mode"], value["returned_decision"] = "shadow", "deny"
            if behavior == "missing_result":
                del value["returned_decision"]
            if behavior == "missing_version":
                del value["policy_version"]
            return self.reply(200, value)
        state["upstream"].append({"body": body, "raw": raw, "headers": dict(self.headers)})
        if body.get("stream"):
            chunks = [b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n', b'data: [DONE]\n\n']
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(sum(map(len, chunks))))
            self.end_headers()
            self.wfile.write(chunks[0])
            self.wfile.flush()
            time.sleep(1)
            self.wfile.write(chunks[1])
            self.wfile.flush()
            return
        self.reply(200, {"id": "fixture-response", "object": "chat.completion", "model": "upstream-model",
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                                      "finish_reason": "stop"}]})


@contextmanager
def fixtures(directory):
    cert, key = directory / "ca.pem", directory / "key.pem"
    issuer_key = directory / "ca-key.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(issuer_key), "-out", str(cert), "-subj", "/CN=OpenAIDR Kong test root",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:3",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    issuer, chain = cert, []
    # Public cross-signed certificates can need several intermediate issuers.
    # Trust only the root, so a shallow Lua TLS verification limit fails this test.
    for index in range(4):
        leaf = index == 3
        child_key = key if leaf else directory / f"intermediate-{index}.key"
        child = directory / f"chain-{index}.pem"
        csr, extensions = directory / "request.csr", directory / "extensions.cnf"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:host.docker.internal\n" if leaf else
            f"basicConstraints=critical,CA:TRUE,pathlen:{2-index}\nkeyUsage=critical,keyCertSign,cRLSign\n"
        )
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(child_key),
            "-out", str(csr), "-subj", "/CN=" + ("host.docker.internal" if leaf else f"test intermediate {index}"))
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer), "-CAkey", str(issuer_key),
            "-set_serial", str(index + 1), "-days", "1", "-extfile", str(extensions), "-out", str(child))
        chain.insert(0, child.read_bytes())
        issuer, issuer_key = child, child_key
    server_chain = directory / "server-chain.pem"
    server_chain.write_bytes(b"".join(chain))
    state = {"gateway_id": str(uuid.uuid4()), "mode": "shadow", "decision": "deny", "capture": False,
             "behavior": "normal", "heartbeat_failure": False, "heartbeat_override": {}, "outcome_status": 200,
             "checks": [], "outcomes": [], "heartbeats": [], "upstream": [], "exports": []}
    servers = [ThreadingHTTPServer(("0.0.0.0", 0), Fixture) for _ in range(2)]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_chain, key)
    servers[0].socket = context.wrap_socket(servers[0].socket, server_side=True)
    for server in servers:
        server.state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield state, cert, f"https://host.docker.internal:{servers[0].server_port}", servers[1].server_port
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


class Kong:
    def __init__(self, directory, artifact, ca, backend, token, model_port):
        self.directory, self.token = directory, token
        # Kong runs as its own UID; Linux bind mounts retain host permissions.
        directory.chmod(0o755)
        self.name = "openaidr-kong-test-" + uuid.uuid4().hex[:10]
        package = directory / "package"
        package.mkdir()
        with tarfile.open(artifact) as archive:
            archive.extractall(package, filter="data")
        self.metadata = json.loads((package / "_build.json").read_text())
        config = {"backend_url": backend, "credential": "{vault://env/openaidr-gateway-token}",
                  "capture_content": True, "timeout_ms": 250, "provider": "configured-provider",
                  "application_name": "Support assistant"}
        self.declaration = {"_format_version": "3.0", "services": [{"id": SERVICE, "name": "model",
            "url": f"http://host.docker.internal:{model_port}/v1/chat/completions",
            "routes": [{"id": ROUTES[name], "name": name, "paths": [path], "strip_path": True, "response_buffering": False}
                       for name, path in (("chat", "/v1/chat/completions"), ("terminated", "/terminated"),
                                          ("ai", "/ai"), ("classifier", "/classifier"),
                                          ("secret-labels", "/secret-labels"), ("unnamed", "/unnamed"))]}],
            "consumers": [{"id": CONSUMER, "username": "authenticated-user",
                           "keyauth_credentials": [{"key": "client-fixture-key"}]}],
            "plugins": [{"name": "key-auth", "service": SERVICE, "config": {"hide_credentials": True}}]
                + [{"name": "openaidr", "route": ROUTES[name], "config": dict(config)}
                   for name in ("chat", "terminated", "ai", "secret-labels", "unnamed")]
                + [{"name": "request-termination", "route": ROUTES["terminated"], "config": {"status_code": 418}},
                   {"name": "ai-proxy", "route": ROUTES["ai"], "config": {
                       "route_type": "llm/v1/chat", "auth": {"header_name": "Authorization", "header_value": "Bearer provider-fixture-key"},
                       "model": {"provider": "openai", "name": "requested-model", "options": {
                           "upstream_url": f"http://host.docker.internal:{model_port}/v1/chat/completions"}}}}]}
        for name in ("secret-labels", "unnamed"):
            consumer = {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, name)), "custom_id": name,
                        "keyauth_credentials": [{"key": name + "-key"}]}
            if name == "secret-labels":
                consumer["username"] = SECRET_LABEL
            self.declaration["consumers"].append(consumer)
            plugin = next(p for p in self.declaration["plugins"] if p.get("route") == ROUTES[name])
            if name == "secret-labels":
                plugin["config"]["application_name"] = SECRET_LABEL
            else:
                plugin["config"].pop("application_name")
        (directory / "kong.json").write_text(json.dumps(self.declaration))
        (directory / "trusted.pem").write_bytes(ca.read_bytes())
        # Read the token from a temporary env file, never from process arguments.
        env = directory / "kong.env"
        env.write_text("OPENAIDR_GATEWAY_TOKEN=" + token + "\n")
        env.chmod(0o600)
        run("docker", "run", "-d", "--rm", "--name", self.name, "--add-host", "host.docker.internal:host-gateway",
            "-p", "127.0.0.1::8000", "-p", "127.0.0.1::8001", "--env-file", str(env),
            "-v", f"{directory}:/fixture:ro", "-e", "KONG_DATABASE=off", "-e", "KONG_DECLARATIVE_CONFIG=/fixture/kong.json",
            "-e", "KONG_ADMIN_LISTEN=0.0.0.0:8001", "-e", "KONG_PLUGINS=bundled,openaidr",
            "-e", "KONG_LUA_PACKAGE_PATH=/fixture/package/?.lua;;", "-e", "KONG_LUA_SSL_TRUSTED_CERTIFICATE=system,/fixture/trusted.pem",
            "-e", "KONG_LUA_SSL_VERIFY_DEPTH=5",
            "-e", "KONG_NGINX_MAIN_ENV=EXISTING_VARIABLE; env OPENAIDR_GATEWAY_TOKEN", "-e", "KONG_NGINX_WORKER_PROCESSES=2",
            "-e", "KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=64k", "-e", "KONG_ANONYMOUS_REPORTS=off", IMAGE)
        try:
            ports = json.loads(run("docker", "inspect", self.name))[0]["NetworkSettings"]["Ports"]
            self.proxy = "http://127.0.0.1:" + ports["8000/tcp"][0]["HostPort"]
            self.admin = "http://127.0.0.1:" + ports["8001/tcp"][0]["HostPort"]
            def ready():
                try:
                    return request(self.admin + "/status")[0] == 200
                except (urllib.error.URLError, ConnectionError):
                    return False
            eventually(ready, timeout=30)
        except BaseException:
            self.close(show_logs=True)
            raise

    def close(self, show_logs=False):
        if show_logs:
            try:
                print(run("docker", "logs", self.name)[-10000:].replace(self.token, "[REDACTED]"))
            except subprocess.CalledProcessError:
                pass
        subprocess.run(["docker", "rm", "-f", self.name], cwd=ROOT, capture_output=True)

    def reload(self):
        status, body = request(self.admin + "/config", {"config": json.dumps(self.declaration)})
        assert status == 201, (status, body.decode()[:500])

    def chat(self, body=None, path="/v1/chat/completions", headers=None):
        return request(self.proxy + path, body or {"model": "requested-model", "messages": [{"role": "user", "content": "Hello"}]},
                       {"Content-Type": "application/json", "apikey": "client-fixture-key", **(headers or {})})

    def pure_checks(self):
        # Run the packaged shared patterns and failure handling in real OpenResty.
        script = r'''
local rules = require "kong.plugins.openaidr.rules"
for _, rule in ipairs(rules.patterns) do
  local _, _, err = ngx.re.find("", rule.pattern, "jo", nil, rule.group or 0)
  assert(not err, rule.name .. ": " .. tostring(err))
end
local redact = require "kong.plugins.openaidr.redact"
for _, secret in ipairs({"ghp_" .. string.rep("a", 36), "oagt_" .. string.rep("b", 43)}) do
  local result, changed = redact.text("hello " .. secret .. " world")
  assert(changed and not result:find(secret, 1, true), "credential was not redacted")
end
local key_pattern = rules.secret_key_pattern
rules.secret_key_pattern = "["
assert(redact.text('{"public":"value"}') == nil, "key inspection errors must omit content")
rules.secret_key_pattern = key_pattern
rules.patterns = {{name="broken", pattern="["}}
assert(redact.text("text") == nil, "regex errors must omit content")
local version = require "kong.plugins.openaidr.version"
assert(require("kong.plugins.openaidr.handler").VERSION == version)
assert(require("version")(version), "Kong must accept the canonical source version")
print("PASS shared redaction rules, runtime failure and canonical Kong version")
'''
        print(run("docker", "exec", self.name, "/usr/local/openresty/bin/resty", "-I", "/fixture/package", "-e", script))


def demo(kong, state):
    print(f"Kong {IMAGE.removeprefix('kong:')} with OpenAIDR {kong.metadata['version']}", flush=True)
    print(f"Proxy: {kong.proxy}/v1/chat/completions", flush=True)
    print("Policy and model services are local fixtures; no dashboard records or model API calls.", flush=True)

    def capture_ready():
        before = len(state["checks"])
        status, _ = kong.chat()
        assert status == 200 and len(state["checks"]) == before + 1
        availability = state["checks"][-1]["availability"]
        assert availability in ("available", "capture_disabled"), availability
        return availability == "available"

    # A startup request may precede the first heartbeat's capture grant.
    eventually(capture_ready)
    print(f"{'Case':<24} {'HTTP':<6} {'Upstream calls':<16} Outcome", flush=True)
    cases = (
        ("Shadow denial", "shadow", "deny", "normal", "Hello", 200, "forwarded", ""),
        ("Enforce allow", "enforce", "allow", "normal", "Hello", 200, "forwarded", ""),
        ("Enforce denial", "enforce", "deny", "normal", "Hello", 403, "blocked", ""),
        ("Backend unavailable", "enforce", "deny", "unavailable", "Hello", 200, "fail_open", "backend_unavailable"),
        ("Secret omitted", "enforce", "deny", "normal", '{"token":"demo-only-value"}', 200, "fail_open", "content_redacted"),
    )
    for name, mode, decision, behavior, content, expected_status, outcome, failure in cases:
        state.update(mode=mode, decision=decision, behavior=behavior)
        body = {"model": "requested-model", "messages": [{"role": "user", "content": content}]}
        checks, dispatched, exports = len(state["checks"]), len(state["upstream"]), len(state["exports"])
        status, response = kong.chat(body)
        assert status == expected_status, (name, status, response[:500])
        assert len(state["checks"]) == checks + 1, name
        check = state["checks"][-1]
        receipt = eventually(lambda: next((item for item in state["outcomes"]
                                          if item["request_id"] == check["request_id"]), None))
        assert receipt["outcome"] == outcome and receipt.get("failure_reason", "") == failure, (name, receipt)
        calls = len(state["upstream"]) - dispatched
        assert calls == (0 if expected_status == 403 else 1), (name, calls)
        if calls:
            assert state["upstream"][-1]["raw"] == json.dumps(body).encode(), name
        else:
            assert json.loads(response)["error"]["code"] == "policy_denied", name
        if failure == "content_redacted":
            assert check["availability"] == "content_redacted" and check["messages"] == [], name
            assert b"demo-only-value" not in b"\n".join(state["exports"][exports:]), name
        else:
            assert check["availability"] == "available" and check["messages"] == body["messages"], name
        print(f"{name:<24} {status:<6} {calls:<16} {receipt['outcome']}", flush=True)
    print("PASS: all five cases matched their expected HTTP, dispatch and evidence results.", flush=True)


def suite(kong, state):
    def checked(body=None, path="/v1/chat/completions", headers=None, status=200, outcome=None, failure=None):
        before = len(state["checks"])
        response = kong.chat(body, path, headers)
        assert response[0] == status, (response[0], response[1][:500])
        assert len(state["checks"]) == before + 1, "Expected one check before provider dispatch"
        check = state["checks"][-1]
        receipt = eventually(lambda: next((o for o in state["outcomes"] if o["request_id"] == check["request_id"]), None))
        if outcome:
            assert receipt["outcome"] == outcome, receipt
        if failure:
            assert receipt.get("failure_reason") == failure, receipt
        return check, receipt

    def refresh_capture(value, failure=False):
        state["capture"], state["heartbeat_failure"] = value, failure
        before = len(state["heartbeats"])
        # A config change forces an immediate heartbeat, avoiding time-dependent sleeps.
        for plugin in kong.declaration["plugins"]:
            if plugin["name"] == "openaidr":
                plugin["config"]["timeout_ms"] = 250 if plugin["config"]["timeout_ms"] == 251 else 251
        kong.reload()
        eventually(lambda: len(state["heartbeats"]) > before)
        time.sleep(0.1)  # Let the acknowledged grant reach the shared worker dictionary.

    kong.pure_checks()
    eventually(lambda: state["heartbeats"])
    check, _ = checked(outcome="fail_open", failure="capture_disabled")
    assert check["messages"] == []
    refresh_capture(True)
    check, receipt = checked(headers={"X-OpenAIDR-Skip": "true", "X-Consumer-ID": "forged", "X-Request-ID": "forged",
                                     "X-Consumer-Username": "forged-user", "X-Application-Name": "forged-app",
                                     "Authorization": "Bearer private-client-key"}, outcome="forwarded")
    assert check["consumer_id"] == CONSUMER and check["route_id"] == ROUTES["chat"] and check["service_id"] == SERVICE
    assert check["consumer_name"] == receipt["consumer_name"] == "authenticated-user"
    assert check["application_name"] == receipt["application_name"] == "Support assistant"
    assert check["provider"] == "configured-provider" and check["request_id"] != "forged"
    assert check["messages"][0]["content"] == "Hello"
    state["mode"], state["decision"] = "enforce", "deny"
    before = len(state["upstream"])
    checked(status=403, outcome="blocked")
    checked(path="/ai", status=403, outcome="blocked")
    assert len(state["upstream"]) == before, "Both proxy paths must block before dispatch"
    state["decision"] = "allow"
    checked(outcome="forwarded")
    checked(path="/ai", outcome="forwarded")
    before = len(state["upstream"])
    checked(path="/terminated", status=418, outcome="unconfirmed")
    assert len(state["upstream"]) == before
    before = len(state["checks"])
    assert kong.chat(headers={"apikey": "invalid"})[0] == 401
    assert len(state["checks"]) == before, "Kong authentication must run before policy"
    assert kong.chat(path="/classifier")[0] == 200
    assert len(state["checks"]) == before, "Separate classifier route must not recurse"
    print("PASS Shadow, Enforce, authenticated identities, native AI Proxy order and confirmed outcomes")

    for name in ("secret-labels", "unnamed"):
        check, receipt = checked(path="/" + name, headers={"apikey": name + "-key"}, outcome="forwarded")
        assert check["consumer_id"] == str(uuid.uuid5(uuid.NAMESPACE_URL, name))
        assert all("consumer_name" not in event and "application_name" not in event for event in (check, receipt))
    print("PASS missing and secret-bearing identity labels are omitted without changing forwarding")

    for behavior, failure in (("unauthorized", "backend_unavailable"), ("unavailable", "backend_unavailable"),
                              ("timeout", "timeout"), ("invalid_json", "invalid_response"),
                              ("oversized_response", "invalid_response"), ("mismatched_request", "invalid_response"),
                              ("invalid_shadow", "invalid_response"), ("missing_result", "invalid_response"),
                              ("missing_version", "invalid_response")):
        state["behavior"], state["decision"] = behavior, "deny"
        started = time.monotonic()
        checked(outcome="fail_open", failure=failure)
        if behavior == "timeout":
            assert time.monotonic() - started < 0.6, "Policy timeout exceeded its total budget"
    state["behavior"], state["decision"] = "normal", "allow"
    print("PASS auth errors, unavailable backend, deadline, malformed/missing/mismatched results fail open")

    benign = [{"role": "user", "content": content} for content in (
        '{"x":1}', '[1,{"label":"public"}]', r'{"label":"\u2603"}',
        '{\n "x": 1, "x": 2\n}', json.dumps({"nested": '{"x":1}'}),
        'tool result: "public" and C:\\Users\\example',
    )]
    benign[1]["role"] = benign[-1]["role"] = "tool"
    body = {"model": "requested-model", "messages": benign}
    check, _ = checked(body, outcome="forwarded")
    assert check["messages"] == benign and state["upstream"][-1]["body"] == body
    assert state["upstream"][-1]["raw"] == json.dumps(body).encode()
    state["decision"] = "deny"
    before = len(state["upstream"])
    check, _ = checked(body, status=403, outcome="blocked")
    assert check["messages"] == benign and len(state["upstream"]) == before
    state["decision"] = "allow"

    secrets = ("ghp_" + "a" * 36, "oagt_" + "b" * 43)
    escaped = "".join("\\u%04x" % ord(character) for character in secrets[1])
    sensitive = ["hello " + secret for secret in secrets] + [
        '{"token":"p?4"}', r'{"\u0074oken":"private-value"}',
        '{"value":"' + escaped + '"}', '"' + escaped + '"',
        '["' + escaped + '"]', '{"' + escaped + '":"public"}',
        json.dumps({"nested": '{"value":"' + escaped + '"}'}),
        '{"value":"' + escaped + '","value":"public"}',
        json.dumps({"nested": '{"value":"' + escaped + '","value":"public"}'}),
    ]
    for content in sensitive:
        body = {"model": "requested-model", "messages": [
            {"role": "system", "content": "Public instructions"}, {"role": "tool", "content": content}]}
        export_start = len(state["exports"])
        check, _ = checked(body, outcome="fail_open", failure="content_redacted")
        assert check["messages"] == [] and state["upstream"][-1]["body"] == body
        assert state["upstream"][-1]["raw"] == json.dumps(body).encode()
        exported = b"\n".join(state["exports"][export_start:])
        assert content.encode() not in exported and json.dumps(content)[1:-1].encode() not in exported
    nested = "public"
    for _ in range(10):
        nested = json.dumps(nested)
    for content in ('{"incomplete":', "[" * 40 + "0" + "]" * 40, nested):
        body = {"model": "requested-model", "messages": [{"role": "user", "content": content}]}
        check, _ = checked(body, outcome="fail_open", failure="unsupported_content")
        assert check["messages"] == [] and state["upstream"][-1]["body"] == body
        assert state["upstream"][-1]["raw"] == json.dumps(body).encode()
    print("PASS decoded JSON keys/values, nested/duplicate secrets, inspection limits and unchanged benign evidence")
    checked({"model": "requested-model", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "private"}}]}]},
            outcome="fail_open", failure="unsupported_content")
    checked({"model": "requested-model", "messages": [{"role": "user", "content": "x" * 66000}]},
            outcome="fail_open", failure="oversized")
    all_exports = b"\n".join(state["exports"])
    for private in (*secrets, "private-client-key", "client-fixture-key", "provider-fixture-key"):
        assert private.encode() not in all_exports, "A secret escaped through telemetry"
    refresh_capture(True, failure=True)
    checked(outcome="fail_open", failure="capture_disabled")
    refresh_capture(False)
    checked(outcome="fail_open", failure="capture_disabled")
    for override in ({"mode": None}, {"version": 1.5}, {"version": 0}):
        state["heartbeat_override"] = override
        refresh_capture(True)
        checked(outcome="fail_open", failure="capture_disabled")
    state["heartbeat_override"] = {}
    for plugin in kong.declaration["plugins"]:
        if plugin["name"] == "openaidr":
            plugin["config"]["capture_content"] = False
    refresh_capture(True)
    checked(outcome="fail_open", failure="capture_disabled")
    for plugin in kong.declaration["plugins"]:
        if plugin["name"] == "openaidr":
            plugin["config"]["capture_content"] = True
    refresh_capture(True)
    print("PASS capture grant, revocation, heartbeat failure, shared redaction and bounded evidence")

    state["heartbeat_override"] = {"guardrail_metrics": False}
    refresh_capture(True)
    _, receipt = checked(outcome="forwarded")
    assert "guardrail_e2e_ms" not in receipt
    state["heartbeat_override"] = {}
    refresh_capture(True)

    connection = http.client.HTTPConnection(kong.proxy.split("://", 1)[1], timeout=10)
    body = {"model": "requested-model", "stream": True, "messages": [{"role": "user", "content": "Hello"}]}
    before = len(state["checks"])
    started = time.monotonic()
    connection.request("POST", "/v1/chat/completions", json.dumps(body), {"Content-Type": "application/json", "apikey": "client-fixture-key"})
    response = connection.getresponse()
    first = response.readline()
    first_elapsed = time.monotonic() - started
    rest = response.read()
    assert response.status == 200 and first_elapsed < 0.75 and time.monotonic() - started >= 1
    assert first + rest == b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\ndata: [DONE]\n\n'
    connection.close()
    assert len(state["checks"]) == before + 1 and state["checks"][-1]["stream"] is True
    assert state["upstream"][-1]["body"] == body
    receipt = eventually(lambda: next((o for o in state["outcomes"]
                                      if o["request_id"] == state["checks"][-1]["request_id"]), None))
    assert 0 <= receipt["guardrail_e2e_ms"] <= receipt["latency_ms"] - 750, receipt
    state["outcome_status"] = 503
    checked(outcome="forwarded")
    time.sleep(0.1)
    refresh_capture(True)
    assert state["heartbeats"][-1]["dropped_events"] >= 1
    assert {r["route_id"] for r in state["heartbeats"][-1]["routes"]} == {value for name, value in ROUTES.items() if name != "classifier"}
    assert state["heartbeats"][-1]["plugin_version"] == kong.metadata["version"]
    print("PASS unchanged incremental streaming, bounded async telemetry and multi-route heartbeat")

    # An untrusted CA must prevent exporting even metadata and the gateway token.
    untrusted = kong.directory / "untrusted"
    untrusted.mkdir()
    with fixtures(untrusted) as (other, _, backend, _):
        other["capture"] = True
        for plugin in kong.declaration["plugins"]:
            if plugin["name"] == "openaidr":
                plugin["config"]["backend_url"] = backend
        kong.reload()
        before = len(state["upstream"])
        assert kong.chat()[0] == 200
        assert len(state["upstream"]) == before + 1 and other["exports"] == []
    print("PASS untrusted backend TLS certificate rejects export and fails open")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="Run five example requests with local policy/model fixtures")
    mode.add_argument("--backend-url", help="Run a real-backend smoke request instead of the fixture policy suite")
    parser.add_argument("--credential-file", type=Path, help="File containing only the real gateway credential")
    parser.add_argument("--ca-file", type=Path, help="Public CA bundle for the real backend")
    args = parser.parse_args()
    if args.backend_url and not (args.credential_file and args.ca_file):
        parser.error("real backend mode requires --credential-file and --ca-file")
    (ROOT / "build/kong").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="integration-", dir=ROOT / "build/kong") as temp:
        directory = Path(temp)
        with fixtures(directory) as (state, ca, backend, model_port):
            if args.demo:
                state["capture"] = True
            token = TOKEN
            if args.backend_url:
                backend, ca, token = args.backend_url, args.ca_file, args.credential_file.read_text().strip()
            kong = Kong(directory, args.artifact.resolve(), ca, backend, token, model_port)
            try:
                if args.backend_url:
                    time.sleep(1)
                    status, _ = kong.chat()
                    assert status in (200, 403), status
                    print(json.dumps({"status": status, "upstream_responses": len(state["upstream"]),
                                      "plugin_version": kong.metadata["version"], "route_id": ROUTES["chat"]}))
                elif args.demo:
                    demo(kong, state)
                else:
                    suite(kong, state)
            except BaseException:
                kong.close(show_logs=True)
                raise
            else:
                kong.close()
                if args.demo:
                    print("Kong test container removed.", flush=True)


if __name__ == "__main__":
    main()
