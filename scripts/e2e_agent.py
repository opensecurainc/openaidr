#!/usr/bin/env python3
"""Run a real agent in a visible CI terminal and retain its redacted JSON stream."""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time


def redact(text, secrets=()):
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|oa(?:et|st)_[A-Za-z0-9_-]{20,})", "[REDACTED]", text)


def run(config):
    output = Path(config["output"])
    output.mkdir(parents=True, exist_ok=True)
    secrets = config.get("redactions", []) + [
        value for key, value in config["env"].items() if key.endswith(("_KEY", "_TOKEN"))]
    started = time.time()
    timed_out = threading.Event()
    print("OpenAIDR E2E: live agent CLI output", flush=True)
    print(config["prompt"], flush=True)
    env = {**os.environ, **config["env"]}
    for key in ("E2E_OPENAI_API_KEY", "E2E_CLAUDE_TOKEN"):
        env.pop(key, None)
    try:
        process = subprocess.Popen(
            config["argv"], cwd=config["cwd"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
    except OSError as error:
        result = {"returncode": 127, "timed_out": False, "error": redact(str(error), secrets)}
        (output / "result.json").write_text(json.dumps(result))
        print(result["error"], flush=True)
        return 127

    def stop():
        timed_out.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = threading.Timer(config.get("timeout", 180), stop)
    timer.start()
    try:
        with (output / "agent.jsonl").open("w") as transcript:
            for line in process.stdout:
                safe = redact(line, secrets)
                transcript.write(safe)
                transcript.flush()
                try:
                    event = json.loads(safe)
                    kind = event.get("type", "event")
                    # Show the real stream in a readable terminal, retaining all
                    # fields in the attachment even when the screen scrolls.
                    payload = event.get("item", event.get("message", event.get("result", event)))
                    print(f"\n[{kind}] {json.dumps(payload, ensure_ascii=False, indent=2)}", flush=True)
                except (ValueError, AttributeError):
                    print(safe, end="", flush=True)
        code = process.wait()
        if timed_out.is_set():
            code = 124
    finally:
        timer.cancel()
        if process.poll() is None:
            stop()
            process.wait()
    result = {"returncode": code, "timed_out": timed_out.is_set(),
              "started_at": started, "duration_seconds": round(time.time() - started, 2)}
    print(f"\nAgent finished: {json.dumps(result)}", flush=True)
    temporary = output / "result.tmp"
    temporary.write_text(json.dumps(result))
    temporary.replace(output / "result.json")
    return code


if __name__ == "__main__":
    path = Path(sys.argv[1])
    config = json.loads(path.read_text())
    path.unlink()  # Do not retain the invocation's credentials on disk.
    raise SystemExit(run(config))
