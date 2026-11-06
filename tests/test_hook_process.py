"""Deterministic Windows process cleanup races at the agent test boundary."""

import os
import subprocess
from types import SimpleNamespace

import pytest

import hook_process


@pytest.mark.parametrize("exiting", [True, False])
def test_windows_timeout_cleanup_observes_pending_exit(monkeypatch, exiting):
    class Process:
        pid = 8
        returncode = None

        def communicate(self, input=None, timeout=None):
            if self.returncode is None:
                assert timeout == 5
                raise subprocess.TimeoutExpired("hook", timeout)
            return "late decision", "private diagnostic"

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            assert 0 < timeout <= 0.25
            if not exiting:
                raise subprocess.TimeoutExpired("hook", timeout)
            self.returncode = 0
            return self.returncode

    process = Process()
    killed = subprocess.CompletedProcess(["taskkill"], 255, b"", b"termination failed")
    monkeypatch.setattr(hook_process, "os", SimpleNamespace(
        name="nt", path=os.path, environ={"SystemRoot": "windows"},
    ))
    monkeypatch.setattr(hook_process, "subprocess", SimpleNamespace(
        Popen=lambda *args, **kwargs: process, run=lambda *args, **kwargs: killed,
        PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired,
        CompletedProcess=subprocess.CompletedProcess,
    ))
    if not exiting:
        with pytest.raises(subprocess.CalledProcessError):
            hook_process.run_hook("hook", input="{}", text=True, timeout=5)
    else:
        result = hook_process.run_hook("hook", input="{}", text=True, timeout=5)
        assert result.timed_out
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")
