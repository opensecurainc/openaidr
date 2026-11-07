"""Proxy passwords stay in the OS credential store and never on a command line."""

import io
import json
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest

from openaidr.sensor import cli, proxy_credentials
from openaidr.sensor.config import Config


@pytest.fixture
def commands(monkeypatch):
    calls, replies = [], []

    def run(command, input=None, **_):
        calls.append((command, input))
        code, out = replies.pop(0) if replies else (0, "")
        return SimpleNamespace(returncode=code, stdout=out, stderr="")

    monkeypatch.setattr(proxy_credentials.subprocess, "run", run)
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: False)
    return calls, replies


def test_macos_keychain_receives_the_password_on_stdin(monkeypatch, commands):
    calls, replies = commands
    monkeypatch.setattr(proxy_credentials.sys, "platform", "darwin")
    proxy_credentials.set("svc@proxy:3128", 'pa"ss\\word')
    (command, stdin), = calls
    assert command == ["/usr/bin/security", "-i"]
    assert stdin == ('add-generic-password -U -s "OpenAIDR sensor proxy" -a "svc@proxy:3128" '
                     '-l "OpenAIDR sensor proxy" -w "pa\\"ss\\\\word"\n')
    replies[:] = [(0, "secret\n"), (44, ""), (1, "")]
    assert proxy_credentials.get("svc@proxy:3128") == "secret"
    assert proxy_credentials.get("svc@proxy:3128") is None
    with pytest.raises(proxy_credentials.CredentialStoreError):
        proxy_credentials.get("svc@proxy:3128")
    assert all("secret" not in " ".join(command) for command, _ in calls)


def test_linux_prefers_secret_service_then_systemd_creds(monkeypatch, commands, tmp_path):
    calls, replies = commands
    monkeypatch.setattr(proxy_credentials.sys, "platform", "linux")
    monkeypatch.setattr(proxy_credentials.os, "name", "posix")
    monkeypatch.setattr(proxy_credentials, "base_dir", lambda: tmp_path)
    monkeypatch.setattr(proxy_credentials.shutil, "which", lambda name: "/usr/bin/" + name)
    proxy_credentials.set("svc@proxy:3128", "pw")
    assert calls[-1] == (["/usr/bin/secret-tool", "store", "--label=OpenAIDR sensor proxy", "service",
                          "openaidr-sensor-proxy", "account", "svc@proxy:3128"], "pw")
    # No Secret Service: encrypt for this user with systemd-creds instead of writing plain text.
    replies[:] = [(1, ""), (0, "")]
    monkeypatch.setattr(proxy_credentials.os, "chmod", lambda *_: None)
    monkeypatch.setattr(proxy_credentials.os, "replace", lambda *_: None)
    proxy_credentials.set("svc@proxy:3128", "pw")
    command, stdin = calls[-1]
    assert command[:3] == ["/usr/bin/systemd-creds", "encrypt", "--user"] and stdin == "pw"
    replies[:] = [(1, "")]
    monkeypatch.setattr(proxy_credentials.shutil, "which",
                        lambda name: None if name == "systemd-creds" else "/usr/bin/" + name)
    with pytest.raises(proxy_credentials.CredentialStoreError, match="No secure credential store"):
        proxy_credentials.set("svc@proxy:3128", "pw")
    assert all("pw" not in command for command, _ in calls)


def test_password_rules_and_system_installs(commands, monkeypatch):
    for bad in ("", "a\nb", "x" * 1025):
        with pytest.raises(ValueError):
            proxy_credentials.set("svc@proxy:3128", bad)
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: True)
    with pytest.raises(ValueError, match="system-wide"):
        proxy_credentials.set("svc@proxy:3128", "pw")
    assert commands[0] == []


@pytest.mark.skipif(os.name != "nt" or not os.environ.get("OPENAIDR_TEST_CREDENTIAL_STORE"),
                    reason="writes a throwaway item to the Windows Credential Manager")
def test_windows_credential_manager_round_trip(monkeypatch):
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: False)
    account = f"openaidr-test-{uuid.uuid4().hex}@proxy:3128"
    try:
        assert proxy_credentials.get(account) is None
        proxy_credentials.set(account, "pässwörd-ü")
        assert proxy_credentials.get(account) == "pässwörd-ü"
    finally:
        proxy_credentials.delete(account)
    assert proxy_credentials.get(account) is None


def test_cli_sets_shows_tests_and_clears(tmp_path, monkeypatch, capsys):
    saved = {}
    monkeypatch.setattr(proxy_credentials, "_backend", lambda: (
        saved.get, saved.__setitem__, lambda account: saved.pop(account, None)))
    monkeypatch.setattr(proxy_credentials, "is_root", lambda: False)
    path = tmp_path / "sensor.yaml"
    Config(path, data_dir=str(tmp_path / "data")).save()
    monkeypatch.setattr(sys, "stdin", io.StringIO("cli-secret\n"))
    assert cli.main(["proxy", "set", "--config", str(path), "--url", "http://proxy.example:3128",
                     "--bypass", "a.example,*.corp.example", "--username", "svc", "--password-stdin"]) == 0
    assert saved == {"svc@proxy.example:3128": "cli-secret"} and "cli-secret" not in path.read_text()
    capsys.readouterr()
    assert cli.main(["proxy", "show", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "mode": "manual", "url": "http://proxy.example:3128", "bypass": ["a.example", "*.corp.example"],
        "username": "svc", "password_saved": True}
    assert cli.main(["proxy", "clear", "--config", str(path)]) == 0
    assert saved == {} and "network" not in Config.load(path)
    assert cli.main(["proxy", "set", "--config", str(path), "--url", "socks5://p:1"]) == 1
    assert "http:// or https://" in capsys.readouterr().err


def test_subprocess_failures_become_store_errors(monkeypatch):
    def broken(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("security", 10)

    monkeypatch.setattr(proxy_credentials.subprocess, "run", broken)
    with pytest.raises(proxy_credentials.CredentialStoreError):
        proxy_credentials._run(["/usr/bin/security", "find-generic-password"])
