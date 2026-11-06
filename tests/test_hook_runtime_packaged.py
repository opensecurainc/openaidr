"""Exercise extraction cleanup with the same bootloader as desktop sensors."""

import os
import json
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import threading

import pytest

from openaidr.sensor import hook_runtime

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" and not (
        sys.platform == "linux" and os.environ.get("OPENAIDR_TEST_PACKAGED_SENSOR")
    ),
    reason="packaged hook boundary needs macOS or a retained Linux sensor",
)


@pytest.fixture(scope="module")
def packaged_hook_runtime(tmp_path_factory):
    """Build the real sensor CLI in the layout used by installed hooks."""
    pytest.importorskip("PyInstaller", reason="desktop build dependency required")
    if retained := os.environ.get("OPENAIDR_TEST_PACKAGED_SENSOR"):
        from PyInstaller.archive.readers import CArchiveReader
        from openaidr.sensor import service

        binary = Path(retained).resolve()
        info = json.loads(subprocess.check_output([binary, "build-info"], text=True, timeout=30))
        work = tmp_path_factory.mktemp("retained-hook-client")
        (work / "hook-client.tar").write_bytes(CArchiveReader(str(binary)).extract("hook-client.tar"))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sys, "frozen", True, raising=False)
            patch.setattr(sys, "_MEIPASS", str(work), raising=False)
            patch.setattr(service, "staged_executable", lambda: str(binary))
            patch.setattr(service, "staged_path", lambda: work / "installed/openaidr")
            staged = Path(service.hook_executable())
        assert staged.is_relative_to(work / "installed/hooks")
        assert json.loads(subprocess.check_output([staged, "build-info"], text=True, timeout=30)) == info
        return staged

    from openaidr.build_info import resolve

    root = Path(__file__).resolve().parents[1]
    work = tmp_path_factory.mktemp("packaged-hook-client")
    info = resolve(root)
    (work / "_build.json").write_text(json.dumps(info))
    entry = work / "entry.py"
    entry.write_text(
        "import multiprocessing\n"
        "if __name__ == '__main__':\n"
        "    multiprocessing.freeze_support()\n"
        "    from openaidr.sensor.cli import main\n"
        "    raise SystemExit(main())\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir",
         "--name", "openaidr-sensor", "--paths", str(root / "src"),
         "--add-data", f"{work / '_build.json'}:openaidr",
         "--collect-data", "openaidr_common",
         "--distpath", str(work / "dist"), "--workpath", str(work / "work"),
         "--specpath", str(work), str(entry)],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(work / "cache")},
    )
    assert result.returncode == 0, result.stderr
    binary = work / "dist/openaidr-sensor/openaidr-sensor"
    assert json.loads(subprocess.check_output([binary, "build-info"], text=True)) == info
    (binary.parent / "build.json").write_text(json.dumps(info))
    with tarfile.open(work / "hook-client.tar", "w") as archive:
        archive.add(binary.parent, arcname=".")
    # Exercise embedding and staging through a real one-file parent too. Only
    # the user's installation directory is substituted in this test entry.
    entry.write_text(
        "import multiprocessing, sys\n"
        "if __name__ == '__main__':\n"
        "    multiprocessing.freeze_support()\n"
        "    if sys.argv[1] == 'stage-test':\n"
        "        from pathlib import Path\n"
        "        from openaidr.sensor import service\n"
        "        service.staged_executable = lambda: sys.executable\n"
        "        service.staged_path = lambda: Path(sys.argv[2]) / 'openaidr'\n"
        "        print(service.hook_executable())\n"
        "    else:\n"
        "        from openaidr.sensor.cli import main\n"
        "        raise SystemExit(main())\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
         "--name", "openaidr", "--paths", str(root / "src"),
         "--add-data", f"{work / '_build.json'}:openaidr",
         "--collect-data", "openaidr_common",
         "--add-data", f"{work / 'hook-client.tar'}:.",
         "--distpath", str(work / "dist"), "--workpath", str(work / "work-parent"),
         "--specpath", str(work), str(entry)],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(work / "cache")},
    )
    assert result.returncode == 0, result.stderr
    staged = Path(subprocess.check_output(
        [work / "dist/openaidr", "stage-test", work / "installed"], text=True, timeout=30,
    ).strip())
    assert staged.is_relative_to(work / "installed/hooks")
    assert json.loads(subprocess.check_output([staged, "build-info"], text=True)) == info
    return staged


@pytest.fixture
def hook_socket_dir():
    # macOS Unix socket paths must fit in 104 bytes, including the terminator.
    with tempfile.TemporaryDirectory(prefix="oa-hook-", dir="/tmp") as directory:
        yield Path(directory)


@pytest.mark.parametrize("mode", ["shadow", "enforce"])
@pytest.mark.parametrize("transport", ["socket", "cli"])
def test_packaged_hook_reaches_listener_inside_native_deadline(tmp_path, hook_socket_dir, packaged_hook_runtime, backend_hook, mode, transport, record_property):
    from openaidr.sensor import hooks
    from openaidr.sensor.config import Config

    cfg = Config(tmp_path / "sensor.yaml", data_dir=str(hook_socket_dir), listen="127.0.0.1:0")
    cfg.save()
    backend = backend_hook(action="deny", mode=mode)
    listener = hooks.HookServer(cfg["listen"], Path(cfg["data_dir"]) / "sensor.sock",
                                lambda _: None, lambda: {}, {}, check=backend)
    stop = threading.Event()
    thread = threading.Thread(target=listener.run, args=(stop,), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not listener.socket_path.exists():
            assert time.monotonic() < deadline, "hook listener did not start"
            time.sleep(0.01)
        command = hooks.command_line(str(packaged_hook_runtime), "PreToolUse", "claude", cfg.path,
                                     health_dir=tmp_path / "health")
        payload = {"session_id": "packaged-shadow", "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": "echo test"}}
        env = {key: value for key, value in os.environ.items()
               if key not in ("OPENAIDR_MANAGED_BRIDGE", "OPENAIDR_SENSOR_CONFIG")}
        if transport == "cli":
            env["OPENAIDR_SENSOR_CONFIG"] = str(cfg.path)
        started = time.monotonic()
        result = subprocess.run(["/bin/sh", "-c", command], input=json.dumps(payload),
                                capture_output=True, text=True, timeout=3, env=env)
        elapsed = time.monotonic() - started
        record_property("hook_seconds", elapsed)
        assert elapsed < 3
        assert result.returncode == 0 and result.stderr == ""
        assert len(backend.requests) == 1 and listener.stats["evaluated"] == 1
        if mode == "shadow":
            assert result.stdout == ""
        else:
            assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        recorded = []
        deadline = time.monotonic() + 2
        while not recorded:
            hook_runtime.collect(tmp_path / "health", recorded.append, sensor_id="packaged-test")
            assert time.monotonic() < deadline, "hook receipt was not recorded"
            time.sleep(0.01)
        assert recorded[0]["hook"]["outcome"] == "succeeded"
    finally:
        stop.set()
        thread.join(2)


def wait_for_cleanup(scratch, preserved=()):
    deadline = time.monotonic() + 2
    while set(scratch.iterdir()) != set(preserved):
        assert time.monotonic() < deadline, "detached cleanup did not complete"
        time.sleep(0.01)


@pytest.fixture(scope="module")
def packaged_sensor(tmp_path_factory):
    pytest.importorskip("PyInstaller", reason="desktop build dependency required")
    root = tmp_path_factory.mktemp("packaged-hook")
    source = root / "sensor.py"
    source.write_text(
        "import multiprocessing\n"
        "if __name__ == '__main__':\n"
        "    multiprocessing.freeze_support()\n"
        "    import json, sys, time\n"
        "    from pathlib import Path\n"
        "    Path(sys.argv[1]).write_text(sys._MEIPASS)\n"
        "    if sys.argv[2] == 'timeout': time.sleep(30)\n"
        "    if sys.argv[2] == 'policy':\n"
        "        from openaidr.core.policy import Policy\n"
        "        from openaidr.core import _policy_worker\n"
        "        policy = Policy({'rules':[{'enabled':True,'action':'deny','match':{'command_regex':'^(a+)+$'}}]})\n"
        "        start = time.monotonic()\n"
        "        decisions = [policy.evaluate({'command':{'text':text}})['action'] for text in ['echo café', 'a'*100000+'!', 'echo next']]\n"
        "        _policy_worker._pool.close()\n"
        "        print(json.dumps({'decisions':decisions,'seconds':time.monotonic()-start,'children':len(multiprocessing.active_children())}), flush=True)\n"
        "    else: print(sys.stdin.read(), flush=True)\n"
        "    raise SystemExit(2 if sys.argv[2] == 'crash' else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
         "--paths", str(Path(__file__).resolve().parents[1] / "src"),
         "--distpath", str(root / "dist"), "--workpath", str(root / "work"),
         "--specpath", str(root), str(source)],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(root / "cache")},
    )
    assert result.returncode == 0, result.stderr
    executable = root / "dist" / "sensor"
    # Warm the OS's executable checks before exercising short hook deadlines.
    subprocess.run([str(executable), str(root / "warmup"), "allow"], input="",
                   text=True, capture_output=True, check=True, timeout=30)
    return executable


def test_packaged_policy_workers_finish_inside_native_deadline(tmp_path, packaged_sensor):
    import json

    process, _, scratch = launch(packaged_sensor, tmp_path, "policy")
    stdout, stderr = process.communicate("", timeout=5)
    assert process.returncode == 0 and stderr == ""
    result = json.loads(stdout)
    assert result["decisions"] == ["allow", "deny", "allow"]
    assert result["seconds"] < 1.5
    assert result["children"] == 0
    wait_for_cleanup(scratch)


def launch(executable, root, case, *, event="PreToolUse", new_session=False, seconds=None):
    marker = root / f"{case}.runtime"
    command = hook_runtime.command([str(executable), str(marker), case], root / "health",
                                   "codex", event)
    if seconds is not None:
        # Startup and concurrency checks must not race the production deadline.
        # Timeout cases keep the installed three-second budget.
        runner = Path(shlex.split(command)[4])
        config = hook_runtime.posix_config(runner.read_text())
        config["seconds"] = seconds
        runner.write_text(hook_runtime.posix_script(config))
    scratch = root / "user's & $(quoted) temp"
    scratch.mkdir(exist_ok=True)
    process = subprocess.Popen(
        ["/bin/sh", "-c", command],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=new_session,
        env={**os.environ, "TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch)},
    )
    return process, marker, scratch


def extracted_runtime(scratch, *, excluding=()):
    deadline = time.monotonic() + 5
    while True:
        runtimes = [p for p in scratch.rglob("_MEI*") if p not in excluding]
        if runtimes:
            return runtimes[0]
        assert time.monotonic() < deadline, "packaged hook did not begin extraction"
        time.sleep(0.01)


@pytest.mark.parametrize("case,event", [("allow", "PreToolUse"), ("deny", "PreToolUse"),
                                        ("crash", "PreToolUse"), ("timeout", "PreToolUse"),
                                        ("timeout", "SessionEnd")])
def test_packaged_hook_removes_extraction(tmp_path, packaged_sensor, case, event):
    process, marker, scratch = launch(packaged_sensor, tmp_path, case, event=event,
                                      seconds=None if case == "timeout" else 10)
    unrelated = scratch / "_MEI-unrelated"
    unrelated.mkdir()
    (unrelated / "keep").write_text("another application")
    payload = '{"permissionDecision":"' + case + '"}'
    stdout, stderr = process.communicate(payload, timeout=3 if case == "timeout" else 8)
    assert (process.returncode, stderr) == (0, "")
    assert stdout.strip() == (payload if case in ("allow", "deny") else "")
    wait_for_cleanup(scratch, [unrelated])
    if marker.exists():
        assert not Path(marker.read_text()).exists()
    assert list(scratch.iterdir()) == [unrelated]
    assert (unrelated / "keep").read_text() == "another application"
    recorded = []
    deadline = time.monotonic() + 2
    while not recorded:
        hook_runtime.collect(tmp_path / "health", recorded.append, sensor_id="test")
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert len(recorded) == 1
    assert recorded[0]["hook"]["outcome"] == ("succeeded" if case in ("allow", "deny") else "failed")


@pytest.mark.parametrize("stop_signal", ["SIGTERM", "SIGKILL"])
def test_cancelled_packaged_hook_removes_extraction(tmp_path, packaged_sensor, stop_signal):
    process, _, scratch = launch(packaged_sensor, tmp_path, "timeout", new_session=True, seconds=10)
    try:
        runtime = extracted_runtime(scratch)
        os.killpg(process.pid, getattr(signal, stop_signal))
        process.communicate(timeout=5)
        deadline = time.monotonic() + 12
        while list(scratch.iterdir()):
            assert time.monotonic() < deadline, "cancelled hook left an extraction directory"
            time.sleep(0.01)
        assert not runtime.exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)


def test_concurrent_packaged_hooks_keep_separate_runtimes(tmp_path, packaged_sensor):
    waiting, _, scratch = launch(packaged_sensor, tmp_path, "deny", seconds=10)
    completing = None
    try:
        waiting_runtime = extracted_runtime(scratch)
        completing, _, _ = launch(packaged_sensor, tmp_path, "allow", seconds=10)
        completing_runtime = extracted_runtime(scratch, excluding=(waiting_runtime,))
        assert waiting_runtime != completing_runtime
        stdout, stderr = completing.communicate('{"permissionDecision":"allow"}', timeout=5)
        assert (completing.returncode, stderr) == (0, "")
        assert stdout.strip() == '{"permissionDecision":"allow"}'
        assert not completing_runtime.exists()
        assert waiting_runtime.is_dir()
        stdout, stderr = waiting.communicate('{"permissionDecision":"deny"}', timeout=5)
        assert stdout.strip() == '{"permissionDecision":"deny"}'
        assert stderr == ""
        assert waiting.returncode == 0
        wait_for_cleanup(scratch)
    finally:
        for process in (waiting, completing):
            if process is not None and process.poll() is None:
                process.communicate(timeout=12)
