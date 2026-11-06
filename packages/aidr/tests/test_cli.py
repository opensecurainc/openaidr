"""The standalone CLI uses saved credentials and preserves SDK outcomes."""

import io
import json
from uuid import UUID, uuid4
import warnings

import httpx
import pytest

from aidr import AIDR, __version__, cli
from aidr.client import Connection
from test_client import TOKEN, TENANT, guardrail_response, package_response


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "aidr-credentials.json"
    monkeypatch.setattr(cli.credentials, "default_path", lambda: path)
    return path


def install_transport(monkeypatch, config, handler):
    def load(path):
        assert path == config
        return Connection("https://api.opensecura.ai", TOKEN, TENANT)

    monkeypatch.setattr(cli.credentials, "load_connection", load)
    monkeypatch.setattr(cli, "AIDR", lambda **options: AIDR(
        **options, transport=httpx.MockTransport(handler)))


def test_help_and_version_preserve_sdk_entrypoint(capsys):
    assert cli.main([]) == 0
    assert "enroll" in capsys.readouterr().out
    with pytest.raises(SystemExit) as result:
        cli.main(["--version"])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


@pytest.mark.parametrize("provided_id", [False, True])
def test_scan_uses_saved_connection_and_prints_id_before_request(config, monkeypatch, capsys, provided_id):
    request_id = str(uuid4())
    errors = io.StringIO()
    monkeypatch.setattr(cli.sys, "stderr", errors)
    calls = []

    def handle(request):
        calls.append(request)
        received_id = request.headers["idempotency-key"]
        assert str(UUID(received_id)) == received_id
        if provided_id:
            assert received_id == request_id
        assert received_id in errors.getvalue()
        assert request.headers["authorization"] == "Bearer " + TOKEN
        assert request.headers["x-opensecura-tenant-id"] == TENANT
        assert json.loads(request.content) == {"packages": [
            {"ecosystem": "pypi", "name": "example-library", "version": "1.0"}]}
        response = package_response(received_id)
        response["results"] = response["results"][:1]
        return httpx.Response(200, json=response)

    install_transport(monkeypatch, config, handle)
    args = ["scan", "--ecosystem", "pypi", "--package", "Example_Library", "--version", "1.0"]
    if provided_id:
        args += ["--request-id", request_id]
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["results"][0]["status"] == "complete"
    assert isinstance(result["results"][0]["checked_at"], str)
    assert result["billing"]["request_id"] in errors.getvalue()
    assert TOKEN not in errors.getvalue()
    assert len(calls) == 1


def test_guardrail_assesses_command_without_executing_it(config, tmp_path, monkeypatch, capsys):
    target = tmp_path / "must-not-exist"
    command = f"touch {target}"
    request_id = str(uuid4())
    calls = []

    def handle(request):
        calls.append(request)
        assert request.url.path == "/v1/services/guardrail/assess"
        assert json.loads(request.content) == {
            "state": {"target_event": {"kind": "command", "command": {"text": command}},
                      "latest_prompt": None, "prior_events": [], "context_limited": True},
            "company_policy": "Protect files.", "timeout_ms": 5000, "max_credits": "1",
        }
        assert not target.exists()
        return httpx.Response(200, json=guardrail_response(request_id))

    install_transport(monkeypatch, config, handle)
    assert cli.main(["guardrail", "--command", command, "--policy", "Protect files.",
                     "--timeout", "5", "--max-credits", "1", "--request-id", request_id]) == 0
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["score"] == 0 and "decision" not in result
    assert request_id in output.err and TOKEN not in output.out + output.err
    assert len(calls) == 1 and not target.exists()


@pytest.mark.parametrize("action", ["scan", "guardrail"])
def test_service_failures_are_nonzero_without_response_or_key_leaks(config, monkeypatch, capsys, action):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(401, text="private provider response " + TOKEN)

    install_transport(monkeypatch, config, handle)
    args = (["scan", "--ecosystem", "npm", "--package", "example", "--version", "1.0.0"]
            if action == "scan" else ["guardrail", "--command", "git status"])
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert not output.out and "Request ID:" in output.err
    assert "Request failed" in output.err and "private provider" not in output.err
    assert TOKEN not in output.err and len(calls) == 1


@pytest.mark.parametrize("args", [
    ["scan", "--ecosystem", "npm", "--package", "example", "--version", "^1.0.0"],
    ["scan", "--ecosystem", "pypi", "--package", "../local", "--version", "1.0"],
    ["guardrail", "--command", "git status", "--request-id", "invalid"],
    ["guardrail", "--command", "git status", "--request-id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"],
    ["guardrail", "--command", "git status", "--timeout", "nan"],
    ["guardrail", "--command", "git status", "--timeout", "inf"],
    ["guardrail", "--command", "git status", "--timeout", "0"],
    ["guardrail", "--command", "git status", "--max-credits", "-1"],
    ["guardrail", "--command", ""],
    ["guardrail", "--command", "x" * 8001],
])
def test_invalid_inputs_make_no_request(config, monkeypatch, capsys, args):
    install_transport(monkeypatch, config, lambda _: pytest.fail("Unexpected request"))
    assert cli.main(args) == 2
    assert not capsys.readouterr().out


@pytest.mark.parametrize("action,function", [("enroll", "enroll_free"), ("status", "status"), ("logout", "logout")])
def test_credential_commands_use_only_selected_aidr_config(config, monkeypatch, capsys, action, function):
    selected = config.parent / "explicit.json"
    calls = []

    def operation(path, **options):
        calls.append((path, options))
        return {"authenticated": action != "logout", "tenant_id": TENANT}

    monkeypatch.setattr(cli.credentials, function, operation)
    args = ["--config", str(selected), action]
    if action == "enroll":
        args += ["--free", "--base-url", "https://api.example.com", "--ca-file", "trust.pem"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["authenticated"] is (action != "logout")
    assert calls == [(selected, {"base_url": "https://api.example.com", "ca_file": "trust.pem"}
                      if action == "enroll" else {})]


@pytest.mark.parametrize("interactive", [False, True])
def test_login_reads_secret_without_putting_it_in_output(config, monkeypatch, capsys, interactive):
    stream = io.StringIO(TOKEN + "\n")
    monkeypatch.setattr(stream, "isatty", lambda: interactive)
    monkeypatch.setattr(cli.sys, "stdin", stream)
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or TOKEN)

    def login(path, api_key, **options):
        assert path == config and api_key == TOKEN
        assert options == {"base_url": "https://api.opensecura.ai", "ca_file": ""}
        return {"authenticated": True, "mode": "api_key", "tenant_id": TENANT}

    monkeypatch.setattr(cli.credentials, "login", login)
    assert cli.main(["login"] + ([] if interactive else ["--api-key-stdin"])) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["authenticated"] is True
    assert TOKEN not in output.out + output.err
    assert bool(prompts) is interactive


def test_noninteractive_login_requires_explicit_stdin_flag(config, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(TOKEN))
    monkeypatch.setattr(cli.credentials, "login", lambda *a, **kw: pytest.fail("Unexpected login"))
    assert cli.main(["login"]) == 2
    output = capsys.readouterr()
    assert "--api-key-stdin" in output.err and TOKEN not in output.out + output.err


def test_login_refuses_getpass_echo_fallback(config, monkeypatch, capsys):
    stream = io.StringIO(TOKEN)
    monkeypatch.setattr(stream, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys, "stdin", stream)

    def fallback(prompt):
        warnings.warn("Input would be echoed", cli.getpass.GetPassWarning)
        pytest.fail("Must not read a secret with terminal echo enabled")

    monkeypatch.setattr(cli.getpass, "getpass", fallback)
    assert cli.main(["login"]) == 2
    output = capsys.readouterr()
    assert "--api-key-stdin" in output.err and TOKEN not in output.out + output.err


@pytest.mark.parametrize("error", [ValueError(TOKEN), OSError(TOKEN), httpx.ConnectError(TOKEN)])
def test_credential_errors_do_not_print_exception_details(config, monkeypatch, capsys, error):
    def fail(path):
        raise error

    monkeypatch.setattr(cli.credentials, "status", fail)
    assert cli.main(["status"]) != 0
    output = capsys.readouterr()
    assert not output.out and TOKEN not in output.err


@pytest.mark.parametrize("action", ["scan", "status"])
def test_missing_credentials_explain_how_to_connect(config, capsys, action):
    args = (["scan", "--ecosystem", "npm", "--package", "example", "--version", "1.0.0"]
            if action == "scan" else ["status"])
    assert cli.main(args) == (2 if action == "scan" else 0)
    output = capsys.readouterr()
    assert "Run aidr enroll --free or aidr login first." in output.err
    if action == "status":
        assert json.loads(output.out)["authenticated"] is False


def test_mistaken_key_argument_is_not_reflected_in_parser_error(config, capsys):
    with pytest.raises(SystemExit) as result:
        cli.main(["login", "--api-key", TOKEN])
    assert result.value.code == 2
    output = capsys.readouterr()
    assert TOKEN not in output.out + output.err
