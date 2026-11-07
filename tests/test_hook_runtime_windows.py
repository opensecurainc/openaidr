"""Run the complete registered command through native Windows shells."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import time

import pytest

from openaidr.sensor import hook_runtime, hooks
from hook_process import run_hook
from test_hook_client import local_hook_sensor, hook_payload
from test_hook_apps import PAYLOADS, installed_command

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows shells required")


@pytest.fixture(scope="module")
def packaged_windows_sensor(tmp_path_factory):
    from openaidr.build_info import resolve

    root = Path(__file__).resolve().parents[1]
    work = tmp_path_factory.mktemp("packaged-windows-client")
    info = resolve(root)
    (work / "_build.json").write_text(json.dumps(info))
    # Same entry and directory packaging as scripts/build_desktop.py.
    entry = work / "entry.py"
    entry.write_text(
        "import multiprocessing\n"
        "if __name__ == '__main__':\n"
        "    multiprocessing.freeze_support()\n"
        "    from openaidr.sensor.cli import main\n"
        "    raise SystemExit(main())\n"
    )
    build = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--name", "openaidr",
         "--paths", str(root / "src"),
         "--add-data", f"{work / '_build.json'};openaidr",
         "--collect-data", "openaidr_common",
         "--distpath", str(work / "dist"), "--workpath", str(work / "build"),
         "--specpath", str(work), str(entry)],
        capture_output=True, text=True, timeout=240,
    )
    assert build.returncode == 0, build.stderr
    executable = work / "dist/openaidr/openaidr.exe"
    assert json.loads(subprocess.check_output([executable, "build-info"], text=True)) == info
    # An inherited Cargo flag must not turn the packaged helper into a client
    # that requires a separately installed runtime.
    with pytest.MonkeyPatch.context() as env:
        env.setenv("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-feature=-crt-static")
        runpy.run_path(str(root / "scripts/build_windows_hook.py"))["build"](
            executable.with_name("openaidr-hook.exe"), info, target_dir=work / "native-target",
        )
    return executable


def test_windows_native_client_requires_no_visual_cpp_runtime(tmp_path, packaged_windows_sensor):
    root = Path(__file__).resolve().parents[1]
    verify = runpy.run_path(str(root / "scripts/build_windows_hook.py"))["verify_runtime_dependencies"]
    # CI already has Visual C++ installed. Inspect actual imports so its global
    # runtime cannot hide the missing-DLL failure seen on a clean Windows VM.
    source = tmp_path / "dynamic.rs"
    source.write_text('fn main() { println!("dynamic runtime fixture"); }')
    dynamic = tmp_path / "dynamic.exe"
    subprocess.run(["rustc", "-Ctarget-feature=-crt-static", str(source), "-o", str(dynamic)],
                   check=True, capture_output=True, text=True, timeout=60)
    with pytest.raises(ValueError, match="external Visual C\\+\\+ runtime DLLs"):
        verify(dynamic)
    verify(packaged_windows_sensor.with_name("openaidr-hook.exe"))


@pytest.mark.parametrize("case", ["allow", "deny", "shadow", "backend_failure", "timeout", "unauthorized"])
@pytest.mark.parametrize("agent,shell", [(agent, shell) for agent in ("claude", "codex")
                                      for shell in ("cmd", "git_bash", "powershell")]
                         # WorkBuddy's default hook shell: Git Bash, else Windows PowerShell.
                         + [("workbuddy", "git_bash"), ("workbuddy", "powershell")])
def test_windows_packaged_hooks_reach_sensor_within_native_deadline(
    tmp_path, packaged_windows_sensor, local_hook_sensor, backend_hook, case, shell, agent, record_property,
):
    config, server, events = local_hook_sensor
    backend = backend_hook(action="deny" if case in ("deny", "shadow") else "allow",
                           mode="shadow" if case == "shadow" else "enforce")

    def check(request, deadline):
        if case == "backend_failure":
            raise OSError("synthetic private failure")
        if case == "timeout":
            time.sleep(5.1)
        result = backend(request, deadline)
        result["reason"] = "café 中文 🦀"
        return result

    server.check = check
    if case == "unauthorized":
        config["telemetry"]["local_token"] = "wrong-token"
        config.save()
    # A real compiled client next to an unusable Python executable proves this
    # path neither starts the full CLI nor depends on its runtime libraries.
    installation = tmp_path / "user's & (test) ! 中文 installation"
    installation.mkdir()
    sensor = installation / "openaidr.exe"
    sensor.write_bytes(b"This Python executable must not run")
    shutil.copy2(packaged_windows_sensor.with_name("openaidr-hook.exe"), installation / "openaidr-hook.exe")
    health = tmp_path / "health ’ % $ `"
    command = hooks.command_line(str(sensor), "PreToolUse", agent, config.path,
                                 health_dir=health)
    assert "powershell" not in command.lower() and "--openaidr-hook" in command
    assert hook_runtime.arguments(command, windows=True) == (hooks.command_args(str(sensor), "PreToolUse", agent, config.path), True)
    system = Path(os.environ["SystemRoot"]) / "System32"
    argv = {
        "git_bash": lambda: f'"{git_bash()}" -c {libuv_quote(command)}',
        "cmd": lambda: f'"{system / "cmd.exe"}" /C "{command}"',
        "powershell": lambda: (f'"{system / "WindowsPowerShell" / "v1.0" / "powershell.exe"}" '
                               f'-NoProfile -NonInteractive -Command {libuv_quote(command)}'),
    }[shell]()
    env = {key: value for key, value in os.environ.items()
           if key not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
    env.update(HTTP_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1")
    for _ in range(1 if case == "timeout" else 3):
        started = time.monotonic()
        result = run_hook(argv, input=json.dumps(hook_payload(), ensure_ascii=False),
                          text=True, encoding="utf-8", timeout=hooks.hook_timeout("PreToolUse", agent), env=env)
        elapsed = time.monotonic() - started
        record_property("hook_seconds", elapsed)
        if case == "timeout":
            assert result.timed_out and (result.stdout, result.stderr) == ("", "")
            break
        assert not result.timed_out and elapsed < 5
        assert (result.returncode, result.stderr) == (0, "")
        if case == "deny":
            assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
            assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecisionReason"] == "café 中文 🦀"
        else:
            assert result.stdout == ""
    if case == "timeout":
        deadline = time.monotonic() + 3
        while not events:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert events[-1]["hook"]["failure_reason"] == "deadline_expired"
    elif case == "unauthorized":
        assert not backend.requests and server.stats["received"] == 0
    elif case != "backend_failure":
        assert len(backend.requests) == 3
        assert all("café 中文" in json.dumps(request, ensure_ascii=False) for request in backend.requests)
    if case != "timeout":
        records = []
        deadline = time.monotonic() + 5
        while len(records) < 3 and time.monotonic() < deadline:
            hook_runtime.collect(health, records.append, sensor_id="native-client-test")
            time.sleep(0.01)
        assert len(records) == 3
        expected = "failed" if case in ("backend_failure", "unauthorized") else "succeeded"
        assert all(r["hook"]["outcome"] == expected for r in records)


@pytest.mark.parametrize("agent", ["copilot", "cursor", "antigravity", "opencode"])
@pytest.mark.parametrize("action", ["allow", "deny", "unavailable"])
def test_windows_new_app_hooks_use_packaged_client(
    tmp_path, packaged_windows_sensor, local_hook_sensor, backend_hook, agent, action,
):
    config, server, events = local_hook_sensor
    backend = backend_hook(action=action)
    server.check = None if action == "unavailable" else backend
    path = tmp_path / ("openaidr.js" if agent == "opencode" else "hooks.json")
    hooks.install(path, str(packaged_windows_sensor), agent, config_path=config.path)
    command = installed_command(path, agent)
    assert "--openaidr-hook" in command
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    argv = f'"{shell}" -NoProfile -NonInteractive -Command {libuv_quote(command)}'
    env = {key: value for key, value in os.environ.items()
           if key not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
    result = run_hook(argv, input=json.dumps(PAYLOADS[agent]), text=True, encoding="utf-8",
                      timeout=hooks.hook_timeout("PreToolUse", agent), env=env)
    assert not result.timed_out and (result.returncode, result.stderr) == (0, "")
    if action == "deny":
        field = {"copilot": "permissionDecision", "cursor": "permission"}.get(agent, "decision")
        assert json.loads(result.stdout)[field] == "deny"
    else:
        assert result.stdout == ""
    if action != "unavailable":
        assert len(backend.requests) == 1 and backend.requests[0]["product"] == hooks.PRODUCTS[agent]
        assert backend.requests[0]["actions"][0]["command"]["text"] == "echo café"


@pytest.mark.parametrize("action", ["allow", "deny"])
@pytest.mark.parametrize("startup_delay", [0, 1200])
def test_windows_native_client_accepts_decision_after_two_seconds(
    tmp_path, packaged_windows_sensor, local_hook_sensor, backend_hook, action, startup_delay,
):
    config, server, events = local_hook_sensor
    backend = backend_hook(action=action)

    def check(request, deadline):
        time.sleep(2.1)
        return backend(request, deadline)

    server.check = check
    path = tmp_path / "hooks.json"
    hooks.install_codex(path, str(packaged_windows_sensor), tmp_path / "config.toml", config.path)
    handler = json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
    # Delay the outer shell before the native client's three-second window starts.
    command = f'Start-Sleep -Milliseconds {startup_delay}; {handler["command"]}'
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    argv = f'"{shell}" -NoProfile -NonInteractive -Command {libuv_quote(command)}'
    started = time.monotonic()
    result = run_hook(argv, input=json.dumps(hook_payload()), text=True, timeout=handler["timeout"])
    assert not result.timed_out and (result.returncode, result.stderr) == (0, "")
    if startup_delay:
        assert time.monotonic() - started > 3
    if action == "deny":
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert result.stdout == ""
    assert len(backend.requests) == 1
    assert events[-1]["hook"]["decision"] == action
    assert "failure_reason" not in events[-1]["hook"]


@pytest.mark.parametrize("case", ["malformed", "oversized", "nonlocal", "bad_response", "late_response", "explicit_config", "managed"])
def test_windows_native_client_rejects_invalid_transport_data(
    tmp_path, packaged_windows_sensor, local_hook_sensor, backend_hook, monkeypatch, case,
):
    config, server, _ = local_hook_sensor
    server.check = backend_hook(action="deny")
    if case == "nonlocal":
        config["listen"] = "192.0.2.1:8377"
        config.save()
    if case in ("bad_response", "late_response"):
        def reply(*_args):
            if case == "late_response":
                time.sleep(3.1)
                return {"output": {"hookSpecificOutput": {"permissionDecision": "deny"}}}
            return {"output": "invalid native output"}
        monkeypatch.setattr(server, "evaluate", reply)
    body = "{" if case == "malformed" else "x" * ((4 << 20) + 1) if case == "oversized" else json.dumps(hook_payload())
    health = tmp_path / "health"
    command = hooks.command_line(str(packaged_windows_sensor), "PreToolUse", "codex", config.path, health_dir=health)
    env = {key: value for key, value in os.environ.items() if key not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
    if case == "explicit_config":
        env["OPENAIDR_SENSOR_CONFIG"] = str(tmp_path / "does-not-exist.yaml")
    if case == "managed":
        # The separate managed bridge retains its existing denial on an
        # unavailable bridge. Ordinary installed hooks still fail open.
        env["OPENAIDR_MANAGED_BRIDGE"] = str(tmp_path / "missing-bridge.json")
    # Allow a synthetic late response to return so the client's own admission
    # check is tested independently of the agent's external process kill.
    argv = f'"{Path(os.environ["SystemRoot"]) / "System32/cmd.exe"}" /C "{command}"'
    result = run_hook(argv, input=body, text=True, timeout=hooks.hook_timeout("PreToolUse", "codex"), env=env)
    assert not result.timed_out and (result.returncode, result.stderr) == (0, "")
    if case in ("explicit_config", "managed"):
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert result.stdout == ""
    if case in ("malformed", "oversized", "nonlocal"):
        assert server.stats["received"] == 0
    records = []
    deadline = time.monotonic() + 5
    while not records and time.monotonic() < deadline:
        hook_runtime.collect(health, records.append, sensor_id="native-client-test")
        time.sleep(0.01)
    assert len(records) == 1
    assert records[0]["hook"]["exit_code"] == (0 if case in ("explicit_config", "managed") else 124 if case == "late_response" else 1)


def test_windows_native_client_never_follows_redirects(tmp_path, packaged_windows_sensor, local_hook_sensor):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    config, _, _ = local_hook_sensor
    calls = []

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            calls.append(self.command)
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            calls.append(self.command)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with ThreadingHTTPServer(("127.0.0.1", 0), Redirect) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            config["listen"] = f"127.0.0.1:{server.server_port}"
            config.save()
            command = hooks.command_line(str(packaged_windows_sensor), "PreToolUse", "codex", config.path,
                                         health_dir=tmp_path / "health")
            argv = f'"{Path(os.environ["SystemRoot"]) / "System32/cmd.exe"}" /C "{command}"'
            result = run_hook(argv, input=json.dumps(hook_payload()), text=True,
                              timeout=hooks.hook_timeout("PreToolUse", "codex"))
            assert not result.timed_out and (result.returncode, result.stdout, result.stderr) == (0, "", "")
            assert calls == ["POST"]
        finally:
            server.shutdown()
            worker.join(5)


@pytest.mark.parametrize("case", ["allow", "deny", "cold_pool_allow", "cold_pool_deny",
                                 "crash", "timeout", "missing", "runner", "syntax"])
def test_windows_hook_boundary(tmp_path, case):
    health = tmp_path / "user's & (test) ! installation" / "health"
    script = "import sys; print(sys.stdin.read()); print('private diagnostic', file=sys.stderr)"
    if case == "crash":
        script += "; sys.exit(2)"
    elif case == "timeout":
        script += "; import time; time.sleep(20)"
    parts = [sys.executable, "-c", script]
    if case == "missing":
        parts[0] = str(tmp_path / "missing.exe")
    # Long argv used to exceed cmd.exe's limit before any guard could run.
    parts.append("x" * 9000)
    command = hook_runtime.command(parts, health, "codex", "PreToolUse", windows=True)
    assert len(command) < 8191
    assert hook_runtime.arguments(command, windows=True) == (parts, True)
    trace = tmp_path / "boundary.trace"
    trace_runner(health, trace)
    if case.startswith("cold_pool_"):
        # A small initial pool must not let the two blocking pipe reads starve
        # the stdin write. Production initialization must supply their workers.
        edit_runner(health, lambda text: text.replace(
            "try {\n    # Drain both output pipes",
            "$initialWorkers = 0; $initialCompletion = 0\n"
            "[Threading.ThreadPool]::GetMinThreads([ref]$initialWorkers, [ref]$initialCompletion)\n"
            "if (-not [Threading.ThreadPool]::SetMinThreads(1, $initialCompletion)) { throw 'test pool setup failed' }\n"
            "try {\n    # Drain both output pipes", 1,
        ))
    if case in ("runner", "syntax"):
        for runner in (health / "launchers").iterdir():
            if case == "runner":
                runner.unlink()
            else:
                runner.write_text("$broken = { invalid script")
    succeeds = case in ("allow", "deny", "cold_pool_allow", "cold_pool_deny")
    payload = '{"permissionDecision":"' + ("deny" if case.endswith("deny") else "allow") + '"}'
    # Error reporting needs PowerShell to initialize before it can be observed.
    # Successful decisions and the native-timeout case keep the agent's limit.
    budget = hooks.hook_timeout("PreToolUse", "codex") if succeeds or case == "timeout" else 10
    started = time.monotonic()
    result = run_hook(command, input=payload, text=True, timeout=budget)
    elapsed = time.monotonic() - started
    if case == "timeout":
        assert result.timed_out and (result.stdout, result.stderr) == ("", "")
        assert not list(health.glob("*.agent"))
        return
    diagnostic = launcher_diagnostic(health, trace, elapsed, expect_record=True)
    assert (result.returncode, result.stderr) == (0, ""), diagnostic
    assert result.stdout.strip() == (payload if succeeds else ""), diagnostic
    assert not result.timed_out and elapsed < budget, diagnostic
    recorded = diagnostic["records"]
    assert len(recorded) == 1, diagnostic
    assert recorded[0]["hook"]["outcome"] == ("succeeded" if succeeds else "failed"), diagnostic
    assert "private diagnostic" not in str(recorded)


def git_bash():
    # Claude Code's lookup: the default installation, then git on PATH.
    git = shutil.which("git")
    for bash in (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe",
                 git and Path(git).resolve().parent.parent / "bin" / "bash.exe"):
        if bash and bash.is_file():
            return str(bash)
    if os.environ.get("CI"):
        pytest.fail("Git Bash is required on the Windows runner")
    pytest.skip("Git Bash is not installed")


def libuv_quote(arg):
    # How Node, and so Claude Code, quotes an argument for CreateProcess.
    if arg and not any(c in arg for c in ' \t"'):
        return arg
    quoted, backslash = [], False
    for c in reversed(arg):
        quoted.append(c)
        if backslash and c == "\\":
            quoted.append("\\")
        elif c == '"':
            backslash = True
            quoted.append("\\")
        else:
            backslash = False
    return '"' + "".join(reversed(quoted)) + '"'


@pytest.mark.parametrize("case", ["allow", "runner", "no_powershell"])
@pytest.mark.parametrize("shell", ["git_bash", "cmd", "powershell"])
def test_windows_hook_runs_in_every_agent_shell(tmp_path, shell, case):
    # Claude Code runs hook commands with Git Bash, or PowerShell without it;
    # Codex runs them with cmd.exe /C. An earlier cmd.exe command line lost its
    # backslashes in Git Bash, never reached the sensor, and wrote failure
    # records into the agent's working directory.
    health = tmp_path / "user's & (test) ! ’installation’ 100%" / "health"
    parts = [sys.executable, "-c", "import sys; print(sys.stdin.read())"]
    command = hook_runtime.command(parts, health, "claude", "PreToolUse", windows=True)
    assert hook_runtime.arguments(command, windows=True) == (parts, True)
    if case == "runner":
        # PowerShell starts but cannot load the runner: record, then allow.
        for runner in (health / "launchers").iterdir():
            runner.unlink()
    elif case == "no_powershell":
        # As if application control blocked PowerShell; no launcher code runs.
        command = command.replace("/powershell.exe", "/missing-powershell.exe")
    project = tmp_path / "project"
    project.mkdir()
    system = Path(os.environ["SystemRoot"]) / "System32"
    argv = {
        "git_bash": lambda: f'"{git_bash()}" -c {libuv_quote(command)}',
        "cmd": lambda: f'"{system / "cmd.exe"}" /C "{command}"',
        "powershell": lambda: (f'"{system / "WindowsPowerShell" / "v1.0" / "powershell.exe"}" '
                               f'-NoProfile -NonInteractive -Command {libuv_quote(command)}'),
    }[shell]()
    payload = '{"permissionDecision":"deny"}'
    result = run_hook(argv, input=payload, text=True, timeout=hooks.hook_timeout("PreToolUse", "claude"), cwd=project)
    records = []
    deadline = time.monotonic() + (5 if case != "no_powershell" else 1)
    while not records and time.monotonic() < deadline:
        hook_runtime.collect(health, records.append, sensor_id="windows-sensor")
        time.sleep(0.01)
    assert list(project.iterdir()) == []
    assert result.stdout.strip() == (payload if case == "allow" else "")
    if case == "no_powershell":
        # Fails open (2 would block), but the shell reports the missing program.
        assert result.returncode not in (0, 2) and records == []
        return
    assert (result.returncode, result.stderr) == (0, "")
    assert [r["hook"]["exit_code"] for r in records] == [0 if case == "allow" else 127]


def test_windows_setup_replaces_hooks_from_earlier_releases(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    sensor = tmp_path / "OpenAIDR" / "openaidr.exe"
    sensor.parent.mkdir()
    sensor.write_bytes(b"")
    health = hook_runtime.directory(settings)
    system = str(Path(os.environ["SystemRoot"]) / "System32")
    user_hook = {"type": "command", "command": "echo user"}
    installed = {}
    for event in hooks.EVENTS:
        # The cmd.exe command line earlier releases installed; Git Bash broke it.
        encoded = hooks.command_line(str(sensor), event, health_dir=health).rsplit(" ", 1)[1]
        legacy = (f'"{system}\\cmd.exe" /d /q /v:off /s /c "("{system}\\WindowsPowerShell\\v1.0\\powershell.exe" '
                  f'-NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded} || (md "{health}" 2>nul)) '
                  '2>nul & exit /b 0"')
        installed[event] = [{"hooks": [{"type": "command", "command": legacy, "timeout": 3}]}]
    installed["PreToolUse"].append({"matcher": "Bash", "hooks": [user_hook]})
    settings.write_text(json.dumps({"hooks": installed}))
    assert hooks.present(settings) and not hooks.installed(settings)

    hooks.install(settings, str(sensor))

    assert hooks.installed(settings)
    repaired = json.loads(settings.read_text())["hooks"]
    for event in hooks.EVENTS:
        ours = [h for group in repaired[event] for h in group["hooks"] if hooks.our_handler(h)]
        assert [h["command"] for h in ours] == [hooks.command_line(str(sensor), event, health_dir=health)]
        assert not ours[0]["command"].startswith('"')
    assert {"matcher": "Bash", "hooks": [user_hook]} in repaired["PreToolUse"]


def test_windows_timeout_stops_descendants(tmp_path):
    child_pid = tmp_path / "child.pid"
    script = ("import subprocess, sys, time; from pathlib import Path; "
              "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']); "
              f"Path({str(child_pid)!r}).write_text(str(p.pid)); time.sleep(20)")
    command = hook_runtime.command([sys.executable, "-c", script], tmp_path / "health",
                                   "claude", "PreToolUse", windows=True)
    result = run_hook(command, input="{}", text=True, timeout=hooks.hook_timeout("PreToolUse", "claude"))
    assert result.timed_out and (result.stdout, result.stderr) == ("", "")
    pid = child_pid.read_text()
    deadline = time.monotonic() + 2
    while True:
        tasks = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32" / "tasklist.exe"),
                                "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, check=True)
        if f'"{pid}"' not in tasks.stdout:
            break
        assert time.monotonic() < deadline
        time.sleep(0.01)


def edit_runner(health, change):
    # The installed runner, edited to simulate the machine changing after setup.
    runner = next((health / "launchers").iterdir())
    script = runner.read_text()
    edited = change(script)
    assert edited != script
    runner.write_text(edited)


def trace_runner(health, trace):
    def instrument(text):
        text = text.replace(
            "$result = 127",
            "$processStarted = -1; $workerExit = -1; $captured = -1; $delivery = -1; "
            "$failure = ''; $failureMessage = ''; $phase = 'initialization'; "
            "$startup = 0; $clock = [Diagnostics.Stopwatch]::StartNew()\n$result = 127",
            1,
        )
        for marker, phase in (
            ("[Console]::OpenStandardInput().CopyTo($process.StandardInput.BaseStream)", "input-forward"),
            ("$process.StandardInput.BaseStream.Close()", "input-close"),
            ("$process.WaitForExit()", "worker-exit-wait"),
        ):
            text = text.replace(marker, f"$phase = '{phase}'\n    {marker}", 1)
        text = text.replace("$null = $process.Start()", "$null = $process.Start(); $processStarted = $startup + $clock.ElapsedMilliseconds", 1)
        text = text.replace("$result = $process.ExitCode", "$workerExit = ([DateTimeOffset]$process.ExitTime - $started).TotalMilliseconds\n        $result = $process.ExitCode", 1)
        text = text.replace("$output = $stdout.Result", "$output = $stdout.Result; $captured = $startup + $clock.ElapsedMilliseconds", 1)
        text = text.replace("if ($result -eq 0 -and $output)", "$delivery = $startup + $clock.ElapsedMilliseconds\n    if ($result -eq 0 -and $output)", 1)
        text = text.replace(
            "} catch { $result = 1 }",
            "} catch { $failure = $_.Exception.GetType().Name; "
            "$failureMessage = $_.Exception.Message.Replace(\"'\", \"''\").Replace(\"`r\", ' ').Replace(\"`n\", ' '); $result = 1 }",
        )
        # Reuse the detached reporter for timings and these synthetic test errors.
        trace_path = str(trace).replace("'", "''")
        return text.replace(
            "$encoded = [Convert]::ToBase64String",
            f'''$report = "[IO.File]::WriteAllText('{trace_path}', 'startup_ms=$startup process_start_ms=$processStarted worker_exit_ms=$workerExit captured_ms=$captured delivery_ms=$delivery result=$result phase=$phase error=$failure message=$failureMessage'); " + $report
    $encoded = [Convert]::ToBase64String''', 1,
        )

    edit_runner(health, instrument)


def launcher_diagnostic(health, trace, elapsed, *, expect_record=False):
    # Read detached evidence only after measuring the agent-visible wait.
    records, detail = [], ""
    deadline = time.monotonic() + 5
    while True:
        hook_runtime.collect(health, records.append, sensor_id="windows-sensor")
        try:
            detail = trace.read_text()
        except OSError:
            pass
        if (records if expect_record else detail) or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    return {"elapsed_s": elapsed, "trace": detail or "no launcher trace", "records": records}


def gone(pid):
    tasks = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32" / "tasklist.exe"),
                            "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                           capture_output=True, text=True, check=True)
    return f'"{pid}"' not in tasks.stdout


@pytest.mark.parametrize("handoff", ["immediate", "delayed", "late_capture"])
def test_windows_unreachable_record_directory_never_delays_the_hook(tmp_path, handoff):
    # A measurement directory that became unreachable after installation, such as
    # a redirected profile on an offline share; 192.0.2.1 is reserved and unrouted.
    health = tmp_path / "health"
    script = "import sys; print(sys.stdin.read())"
    command = hook_runtime.command([sys.executable, "-c", script], health, "codex", "PreToolUse",
                                   windows=True)
    unreachable = r"\\192.0.2.1\share\openaidr-hook-health"
    edit_runner(health, lambda text: text.replace(json.dumps(str(health)), json.dumps(unreachable)))
    trace = tmp_path / "handoff.trace"
    trace_runner(health, trace)

    def instrument(text):
        if handoff == "late_capture":
            text = text.replace("$output = $stdout.Result", "Start-Sleep -Seconds 3; $output = $stdout.Result", 1)
        if handoff == "delayed":
            # Release process resources after a timely response, before delivery.
            text = text.replace("$process.Dispose()", "$process.Dispose(); Start-Sleep -Seconds 3", 1)
        return text

    if handoff != "immediate":
        edit_runner(health, instrument)
    payload = '{"permissionDecision":"deny"}'
    started = time.monotonic()
    budget = hooks.hook_timeout("PreToolUse", "codex")
    result = run_hook(command, input=payload, text=True, timeout=budget)
    elapsed = time.monotonic() - started
    diagnostic = launcher_diagnostic(health, trace, elapsed)
    expected = payload if handoff == "immediate" else ""
    assert (result.returncode, result.stdout.strip(), result.stderr) == (0, expected, ""), diagnostic
    assert not result.timed_out and elapsed < budget, diagnostic
    if handoff != "immediate":
        assert "result=124" in diagnostic["trace"], diagnostic


@pytest.mark.parametrize("termination", ["missing", "ineffective"])
def test_windows_agent_terminates_hook_without_launcher_taskkill(tmp_path, termination):
    health, pid_file = tmp_path / "health", tmp_path / "hook.pid"
    # A long-running descendant that inherits every handle the hook holds,
    # including the agent's output pipe, so the agent waits until it is gone.
    # The hook enters its job first, as the sensor's hook command does.
    script = (f"import os, subprocess, sys, time; from pathlib import Path; "
              f"from openaidr.sensor import hook_runtime; hook_runtime.contain_descendants(); "
              f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'], close_fds=False); "
              f"Path({str(pid_file)!r}).write_text(f'{{os.getpid()}} {{child.pid}}'); time.sleep(20)")
    command = hook_runtime.command([sys.executable, "-c", script], health, "claude", "PreToolUse",
                                   windows=True)
    trace = tmp_path / "termination.trace"
    trace_runner(health, trace)
    if termination == "missing":
        # As if application control denied taskkill.exe.
        edit_runner(health, lambda text: text.replace("\\System32\\taskkill.exe", "\\System32\\missing-taskkill.exe"))
    else:
        # A helper that starts successfully but does not end the hook.
        edit_runner(health, lambda text: text.replace(
            r'detach "$env:SystemRoot\System32\taskkill.exe" "/PID $($process.Id) /T /F"',
            r'detach "$env:SystemRoot\System32\cmd.exe" "/d /c exit 0"',
        ))
    started = time.monotonic()
    result = run_hook(command, input="{}", text=True, timeout=hooks.hook_timeout("PreToolUse", "claude"))
    elapsed = time.monotonic() - started
    deadline = time.monotonic() + 2
    try:
        pids = pid_file.read_text().split()
    except OSError:
        pids = []
    remaining_pids = []
    for pid in pids:
        while not gone(pid):
            if time.monotonic() >= deadline:
                remaining_pids.append(pid)
                break
            time.sleep(0.01)
    diagnostic = {"elapsed_s": elapsed, "pids": pids}
    assert result.timed_out and (result.stdout, result.stderr) == ("", ""), diagnostic
    assert pids, diagnostic
    assert not remaining_pids, (remaining_pids, diagnostic)
