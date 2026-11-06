"""The installed launcher bounds startup and leaves housekeeping off the path."""

import json
import os
import shlex
import subprocess
import sys
import time

import pytest

from openaidr.sensor import hook_runtime
from hook_process import run_hook


@pytest.mark.skipif(os.name == "nt", reason="POSIX native launcher")
@pytest.mark.parametrize("stage", ["clock", "setup", "cleanup", "report", "late_response", "shell_profile"])
def test_launcher_deadline_includes_setup_and_excludes_housekeeping(tmp_path, monkeypatch, stage):
    delayed = tmp_path / "delayed"
    delayed.write_text("#!/bin/sh\n/bin/sleep 4\nexec \"$@\"\n")
    delayed.chmod(0o700)
    watched = hook_runtime.WATCHED
    posix = hook_runtime.POSIX
    if stage == "clock":
        watched = watched.replace("/usr/bin/perl", f"{shlex.quote(str(delayed))} /usr/bin/perl")
    elif stage == "setup":
        watched = watched.replace("/usr/bin/mktemp", f"{shlex.quote(str(delayed))} /usr/bin/mktemp")
    elif stage == "cleanup":
        watched = watched.replace("/bin/rm", f"{shlex.quote(str(delayed))} /bin/rm")
    elif stage == "report":
        posix = posix.replace("/bin/mkdir", f"{shlex.quote(str(delayed))} /bin/mkdir")
    posix = posix.replace(shlex.quote(hook_runtime.WATCHED), shlex.quote(watched))
    monkeypatch.setattr(hook_runtime, "POSIX", posix)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    profile = tmp_path / "bashenv"
    profile.write_text("/bin/sleep 4\nprintf 'unexpected profile output'\n")
    source = (
        "import json, os, time; "
        "budget = int(os.environ['OPENAIDR_HOOK_DEADLINE_NS']) - time.time_ns(); "
        "assert 0 < budget <= 2100000000; "
        + ("time.sleep(2.65); " if stage == "late_response" else "")
        + "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}}))"
    )
    health = tmp_path / "health"
    command = hook_runtime.command([sys.executable, "-c", source], health, "codex", "PreToolUse")
    started = time.monotonic()
    result = run_hook(
        ["/bin/sh", "-c", command], input="x" * (4 << 20) if stage == "setup" else "{}", text=True, timeout=3,
        env={**os.environ, "TMPDIR": str(scratch), "BASH_ENV": str(profile)},
    )
    elapsed = time.monotonic() - started
    assert not result.timed_out
    assert (result.returncode, result.stderr) == (0, "")
    assert elapsed < 3
    if stage in ("clock", "setup", "late_response"):
        assert result.stdout == ""
    else:
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert elapsed < 1
    # Housekeeping is explicitly asynchronous. Wait for its own completion so
    # tests verify eventual cleanup without counting it toward the action delay.
    recorded = []
    deadline = time.monotonic() + 5
    while not recorded or any(scratch.iterdir()):
        hook_runtime.collect(health, recorded.append, sensor_id="deadline-test")
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert len(recorded) == 1
    expected = "failed" if stage in ("clock", "setup", "late_response") else "succeeded"
    assert recorded[0]["hook"]["outcome"] == expected


@pytest.mark.skipif(os.name == "nt", reason="Unix socket client")
@pytest.mark.parametrize("fraction_ns", [100_000_000, 850_000_000])
@pytest.mark.parametrize("clock", ["perl", "date"])
@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_socket_deadline_preserves_fractional_start(tmp_path, monkeypatch, fraction_ns, clock, decision):
    import socketserver
    import tempfile
    import threading
    from pathlib import Path
    from urllib.parse import parse_qs, urlsplit

    started = 1_900_000_000_000_000_000 + fraction_ns
    precise = tmp_path / "clock"
    precise.write_text(
        "#!/bin/sh\n"
        # A whole-second lookup reproduces the old deadline calculation.
        f"case \"$*\" in *+%s) printf '1900000000';; *) printf '{started}';; esac\n"
    )
    precise.chmod(0o700)
    watched = hook_runtime.WATCHED.replace("/bin/date", shlex.quote(str(precise)))
    watched = watched.replace("/usr/bin/perl", shlex.quote(str(precise)) if clock == "perl" else "/missing/perl")
    monkeypatch.setattr(hook_runtime, "POSIX", hook_runtime.POSIX.replace(
        shlex.quote(hook_runtime.WATCHED), shlex.quote(watched),
    ))
    captured = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            query = parse_qs(urlsplit(self.rfile.readline().decode().split()[1]).query)
            captured.append(query)
            length = 0
            while line := self.rfile.readline().strip():
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            self.rfile.read(length)
            # A 1.8-second assessment must fit regardless of the start fraction.
            # Use a fixed clock instead of scheduling a launch near a wall-clock
            # boundary, which would make this regression test nondeterministic.
            timely = int(query["deadline"][0]) > started + 1_800_000_000
            body = (b'{"hookSpecificOutput":{"permissionDecision":"deny"}}'
                    if decision == "deny" else b"")
            status = b"200 OK" if timely else b"503 Service Unavailable"
            self.wfile.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body)

    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        sock = str(Path(short) / "sensor.sock")
        command = hook_runtime.command(["/missing/openaidr", "hook", "PreToolUse"],
                                       tmp_path / "health", "claude", "PreToolUse", socket_path=sock)
        with socketserver.UnixStreamServer(sock, Handler) as server:
            worker = threading.Thread(target=server.handle_request, daemon=True)
            worker.start()
            env = {k: v for k, v in os.environ.items()
                   if k not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
            result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True,
                                    capture_output=True, timeout=3, env=env)
            worker.join(2)
        assert (result.returncode, result.stderr) == (0, "")
        assert captured[0]["started"] == [str(started)]
        assert captured[0]["deadline"] == [str(started + 2_100_000_000)]
        assert captured[0]["timeout_owner"] == ["sensor"]
        if decision == "deny":
            assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert result.stdout == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX native launcher")
@pytest.mark.parametrize("clock_output", ["", "1900000000N", "not a timestamp"])
def test_launcher_fails_silently_when_no_precise_clock_is_available(tmp_path, monkeypatch, clock_output):
    clock = tmp_path / "clock"
    clock.write_text(f"#!/bin/sh\nprintf '%s' {shlex.quote(clock_output)}\n")
    clock.chmod(0o700)
    watched = hook_runtime.WATCHED.replace("/usr/bin/perl", shlex.quote(str(clock)))
    watched = watched.replace("/bin/date", shlex.quote(str(clock)))
    monkeypatch.setattr(hook_runtime, "POSIX", hook_runtime.POSIX.replace(
        shlex.quote(hook_runtime.WATCHED), shlex.quote(watched),
    ))
    command = hook_runtime.command(["/bin/echo", "unexpected hook output"],
                                   tmp_path / "health", "codex", "PreToolUse")
    result = subprocess.run(["/bin/sh", "-c", command], input="{}", text=True,
                            capture_output=True, timeout=3)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


def test_failed_delivery_receipt_is_distinct_and_retryable():
    delivered = []
    failed = []

    def record_failure(event):
        failed.append(event)
        if len(failed) == 1:
            raise OSError("backend unavailable")

    pending = hook_runtime.PendingDecisions(delivered.append, failed=record_failure)
    event = {"hook": {"execution_id": "abcdef", "decision": "deny", "delivery": "pending"}}
    pending.stage(event)
    measurement = {"hook": {"execution_id": "abcdef", "outcome": "failed"}}
    with pytest.raises(OSError):
        pending.complete(measurement)
    pending.complete(measurement)
    pending.complete(measurement)
    assert delivered == []
    assert len(failed) == 2
    assert failed[0]["hook"]["delivery"] == "failed"
    assert pending.size == 0

    pending.stage(event)
    pending.complete({"hook": {"execution_id": "abcdef", "outcome": "succeeded"}})
    assert delivered[0]["hook"]["delivery"] == "delivered"


@pytest.mark.parametrize("code,reason", [(28, ""), (124, ""), (137, ""), (22, "deadline_expired")])
def test_early_timeout_receipt_waits_for_request_correlation(code, reason):
    delivered, failed = [], []
    pending = hook_runtime.PendingDecisions(delivered.append, failed=failed.append)
    pending.complete({"hook": {"execution_id": "abcdef", "outcome": "failed", "exit_code": code}})
    pending.stage({"hook": {"execution_id": "abcdef", "request_id": "original-request",
                             "decision": "allow", "failure_reason": reason}})
    assert delivered == failed == [], "Pairing and reporting must stay off the hook thread"
    pending.flush()
    pending.flush()
    assert len(failed) == 1 and delivered == []
    assert failed[0]["hook"]["delivery"] == "timed_out"
    assert failed[0]["hook"]["request_id"] == "original-request"
    assert not pending.entries and not pending.receipts


@pytest.mark.skipif(os.name == "nt", reason="Unix socket client")
@pytest.mark.parametrize("failure", ["redirect", "truncated", "malformed", "stalled", "overloaded"])
def test_socket_transport_discards_invalid_or_incomplete_http_responses(tmp_path, failure):
    import socketserver
    import tempfile
    import threading
    from pathlib import Path

    body = b'{"hookSpecificOutput":{"permissionDecision":"deny"}}'
    release = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.rfile.readline()
            length = 0
            while line := self.rfile.readline().strip():
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            self.rfile.read(length)
            if failure == "stalled":
                assert release.wait(4)
            elif failure == "malformed":
                self.wfile.write(b"not an HTTP response\r\n\r\n" + body)
            elif failure == "overloaded":
                self.wfile.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n")
            else:
                status = b"302 Found" if failure == "redirect" else b"200 OK"
                size = len(body) + (100 if failure == "truncated" else 0)
                self.wfile.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(size).encode() + b"\r\n\r\n" + body)

    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        sock = str(Path(short) / "sensor.sock")
        health = tmp_path / "health"
        command = hook_runtime.command(["/missing/openaidr", "hook", "PreToolUse"], health,
                                       "claude", "PreToolUse", socket_path=sock)
        with socketserver.UnixStreamServer(sock, Handler) as server:
            worker = threading.Thread(target=server.handle_request, daemon=True)
            worker.start()
            env = {k: v for k, v in os.environ.items()
                   if k not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
            started = time.monotonic()
            result = run_hook(["/bin/sh", "-c", command], input="{}", text=True,
                              timeout=3, env=env)
            release.set()
            worker.join(2)
        assert not result.timed_out and time.monotonic() - started < 3
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
        recorded = []
        deadline = time.monotonic() + 2
        while not recorded:
            hook_runtime.collect(health, recorded.append, sensor_id="socket-test")
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert recorded[0]["hook"]["outcome"] == "failed"
