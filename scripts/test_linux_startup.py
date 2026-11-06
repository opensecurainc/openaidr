#!/usr/bin/env python3
"""Confirm that the packaged Linux app renders its first-run controls."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pyatspi


def accessible_names(node):
    names = set()
    try:
        if node.name:
            names.add(node.name)
        for child in node:
            names.update(accessible_names(child))
    except (RuntimeError, LookupError):
        pass
    return names


def main():
    executable, output, format = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if os.geteuid() == 0:
        raise ValueError("Launch the app as the disposable test user, not root")
    command = [str(executable)]
    if format == "appimage":
        command.append("--appimage-extract-and-run")
    environment = {**os.environ, "WEBKIT_DISABLE_DMABUF_RENDERER": "1", "PYTHONTZPATH": "/nonexistent"}
    with (output / "startup.log").open("w") as log:
        app = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                               env=environment, start_new_session=True)
        try:
            deadline = time.monotonic() + 90
            names = set()
            while time.monotonic() < deadline:
                if app.poll() is not None:
                    raise RuntimeError(f"App exited before setup appeared: {app.returncode}")
                for candidate in pyatspi.Registry.getDesktop(0):
                    names.update(accessible_names(candidate))
                if "Continue for free" in names:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("The packaged app did not render its first-run controls")
            (output / "result.json").write_text(json.dumps({
                "format": format, "first_run_visible": True, "controls": sorted(names),
            }, indent=2) + "\n")
        finally:
            (output / "accessible-controls.json").write_text(json.dumps(sorted(names), indent=2) + "\n")
            try:
                os.killpg(app.pid, signal.SIGTERM)
                app.wait(timeout=10)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(app.pid, signal.SIGKILL)
                app.wait()


if __name__ == "__main__":
    main()
