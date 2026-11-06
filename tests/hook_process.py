"""Exercise the installed command with an external agent's process deadline."""

import os
import signal
import subprocess


def run_hook(command, *, input=None, timeout=3, **kwargs):
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=os.name != "nt", **kwargs,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            killed = subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "taskkill.exe"),
                                     "/PID", str(process.pid), "/T", "/F"], capture_output=True)
            # taskkill can race with an exit that is not yet visible through
            # the process handle. Reap it briefly before reporting a failed
            # cancellation; a process that remains alive still fails the test.
            if killed.returncode:
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    killed.check_returncode()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)
        # Agents discard even partial stdout when they cancel a timed-out hook.
        stdout = stderr = "" if kwargs.get("text") else b""
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    result.timed_out = timed_out
    return result
