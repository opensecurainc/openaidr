"""Daily version checks, independent of the desktop window."""

import json
import logging
import math
from pathlib import Path
from time import time

from openaidr.core.event import now
from openaidr.core.files import atomic_write

INTERVAL = 24 * 60 * 60


def cache_path(config):
    return Path(config["data_dir"]) / "update-check.json"


def identity(config):
    return {
        key: config.get(key, "") for key in ("server_url", "sensor_id", "tenant_id")
    }


def read_cache(config):
    try:
        cached = json.loads(cache_path(config).read_text())
        if not isinstance(cached, dict) or cached.get("identity") != identity(config):
            return {}
        attempted = cached.get("attempted_at")
        if not isinstance(attempted, (int, float)) or not math.isfinite(attempted):
            return {}
        latest, checked = cached.get("latest", ""), cached.get("checked_at", "")
        if (
            not isinstance(latest, str)
            or len(latest) > 128
            or not isinstance(checked, str)
        ):
            return {}
        return {"attempted_at": attempted, "latest": latest, "checked_at": checked,
                **({"build": cached["build"]} if isinstance(cached.get("build"), dict) else {})}
    except (OSError, ValueError, OverflowError):
        return {}


class UpdateChecker:
    def __init__(self, config):
        self.config = config
        self.result = read_cache(config)

    def save(self):
        try:
            atomic_write(
                cache_path(self.config),
                json.dumps(
                    {
                        "identity": identity(self.config),
                        **self.result,
                    }
                ),
            )
        except OSError as exc:
            # An unwritable cache must not stop collection or reset this process's timer.
            logging.warning("could not save update check: %s", exc)

    def check_due(self, client):
        timestamp = time()
        attempted = self.result.get("attempted_at")
        if attempted is not None and 0 <= timestamp - attempted < INTERVAL:
            return
        # Persist attempts too, so a failure or restart cannot hammer the server.
        # A backwards clock adjustment makes the check due once to reset the schedule.
        self.result = {**self.result, "attempted_at": timestamp}
        self.save()
        try:
            result = client.post("version", {})
            latest = result.get("version")
            if not isinstance(latest, str) or not latest.strip() or len(latest) > 128:
                raise ValueError("the server did not report a valid version")
            self.result = {"attempted_at": timestamp, "latest": latest.strip(), "checked_at": now(),
                           **({"build": result["build"]} if isinstance(result.get("build"), dict) else {})}
            self.save()
        except Exception as exc:
            # Keep the last successful result and retry at the next daily check.
            logging.warning("update check failed: %s", exc)
