"""Periodic software snapshots, with a private cache for delivery retries."""

import copy
import json
import logging
import sys
import threading
import httpx
from datetime import datetime, timezone
from pathlib import Path

from openaidr.core.event import now
from openaidr.core.files import atomic_write
from .inventory import collect_inventory
from . import component_inventory


def settings(config):
    values = config.get("inventory", {})
    if not isinstance(values, dict):
        raise ValueError("inventory must be a mapping")
    enabled = values.get("enabled", True)
    interval = values.get("interval_s", 21600)
    if type(enabled) is not bool:
        raise ValueError("inventory.enabled must be a boolean")
    if type(interval) is not int or not 300 <= interval <= 604800:
        raise ValueError("inventory.interval_s must be between 300 and 604800")
    component_inventory.settings(config)
    return {"enabled": enabled, "interval_s": interval}


class InventoryService:
    def __init__(self, config, client, paused=lambda: False, *, components=False):
        self.options = settings(config)
        self.local = config.get("connection_mode") in ("free", "api_key")
        self.client, self.paused = client, paused
        self.component_options = (
            component_inventory.settings(config) if components else None
        )
        self.upload_skill_bundles = config.get("inventory", {}).get("upload_skill_bundles", True)
        if type(self.upload_skill_bundles) is not bool:
            raise ValueError("inventory.upload_skill_bundles must be a boolean")
        if components:
            self.options["enabled"] &= (
                self.component_options["enabled"] and sys.platform in ("darwin", "linux", "win32")
            )
        else:
            self.options["enabled"] &= sys.platform != "darwin"
        self.path = Path(config["data_dir"]) / (
            "component-inventory.json" if components else "application-inventory.json"
        )
        self.endpoint = (
            "inventory/snapshots" if components else "inventory/applications"
        )
        self.identity = [config["server_url"], config["sensor_id"]]
        if self.local:
            from .usage import identity

            self.identity = ["local", identity(config), config["connection_mode"], self.options]
        if components:
            # Changing the scan scope discards pending data from the former scope.
            self.identity.append(self.component_options)
        self.lock = threading.Lock()
        self.state, self.last_error = {}, ""
        if self.options["enabled"]:
            try:
                with self.path.open(encoding="utf-8") as cache:
                    saved = json.loads(cache.read(((8 if components else 5) << 20) + 1))
                snapshot = saved.get("snapshot", {})
                if (
                    saved.get("identity") == self.identity
                    and snapshot.get("schema_version") == 1
                    and (
                        isinstance(snapshot.get("roots"), list)
                        and len(snapshot["roots"]) <= 256
                        and all(
                            isinstance(root, dict)
                            and root.get("source")
                            in component_inventory.SOURCES.values()
                            and isinstance(root.get("root"), str)
                            and root.get("scope")
                            in ("system", "user", "project", "unknown")
                            and isinstance(root.get("components"), list)
                            and root.get("status")
                            in ("ok", "partial", "error", "unavailable")
                            for root in snapshot["roots"]
                        )
                        if components
                        else isinstance(snapshot.get("applications"), list)
                        and isinstance(snapshot.get("sources"), list)
                    )
                    and self._timestamp(snapshot["collected_at"]).tzinfo is not None
                ):
                    self.state = saved
            except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
                # An unusable cache is replaced by a fresh scan, never uploaded.
                pass

    @staticmethod
    def _timestamp(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _save(self, state):
        atomic_write(self.path, json.dumps(state, ensure_ascii=True))
        with self.lock:
            self.state = state

    def status(self):
        with self.lock:
            snapshot = self.state.get("snapshot", {})
            result = dict(
                self.options,
                collected_at=snapshot.get("collected_at"),
                last_sent_at=self.state.get("last_sent_at"),
                pending=not self.local and bool(snapshot) and not self.state.get("acknowledged", False),
                last_error=self.last_error,
            )
            if self.component_options is None:
                result.update(
                    applications=len(snapshot.get("applications", [])),
                    sources=copy.deepcopy(snapshot.get("sources", [])),
                )
            else:
                roots = snapshot.get("roots", [])
                result.update(
                    components=sum(len(root["components"]) for root in roots),
                    roots=len(roots),
                    coverage={
                        status: sum(root["status"] == status for root in roots)
                        for status in ("ok", "partial", "error", "unavailable")
                    },
                )
            return result

    def sync_once(self, stop=None):
        if not self.options["enabled"] or self.paused() or (stop and stop.is_set()):
            return
        self._send_pending(stop)
        if self.paused() or (stop and stop.is_set()):
            return
        snapshot = self.state.get("snapshot")
        age = (
            (
                datetime.now(timezone.utc) - self._timestamp(snapshot["collected_at"])
            ).total_seconds()
            if snapshot
            else None
        )
        if self.state.get("force_refresh") or age is None or age < 0 or age >= self.options["interval_s"]:
            snapshot = (
                collect_inventory()
                if self.component_options is None
                else component_inventory.collect_inventory(
                    self.component_options,
                    (snapshot or {}).get("roots", []),
                    cancelled=lambda: self.paused() or bool(stop and stop.is_set()),
                )
            )
            if self.paused() or (stop and stop.is_set()):
                return
            self._save(
                dict(
                    identity=self.identity,
                    snapshot=snapshot,
                    acknowledged=self.local,
                    last_sent_at=self.state.get("last_sent_at"),
                )
            )
        self._send_pending(stop)
        if (not self.local and self.component_options is not None and self.upload_skill_bundles
                and self.state.get("skill_scanning") and not self.state.get("bundles_sent")
                and not self.paused() and not (stop and stop.is_set())):
            from .skill_bundles import upload

            try:
                if upload(self.client, self.state["snapshot"], lambda: self.paused() or bool(stop and stop.is_set())):
                    self._save(dict(self.state, bundles_sent=True))
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 409:
                    self._save(dict(self.state, force_refresh=True))
                raise
        with self.lock:
            self.last_error = ""

    def _send_pending(self, stop):
        if self.local:
            return
        snapshot = self.state.get("snapshot")
        if (
            snapshot
            and not self.state.get("acknowledged")
            and not self.paused()
            and not (stop and stop.is_set())
        ):
            reply = self.client.post(self.endpoint, snapshot)
            enabled = isinstance(reply, dict) and reply.get("skill_scanning", {}).get("enabled") is True
            self._save(dict(self.state, acknowledged=True, last_sent_at=now(), skill_scanning=enabled))

    def run(self, stop):
        backoff = 30
        while not stop.is_set():
            try:
                self.sync_once(stop)
                backoff = 30
            except Exception as exc:
                # Inventory failures must not stop telemetry forwarding or heartbeats.
                with self.lock:
                    self.last_error = str(exc)
                logging.warning("%s failed: %s", self.endpoint, exc)
                backoff = min(300, backoff * 2)
            stop.wait(backoff)
