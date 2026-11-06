"""Recover directory timelines for sessions requested by the enrolled backend."""

from collections import OrderedDict
from datetime import datetime, timezone
import json
import re
import sqlite3
import threading

from openaidr.core.redact import redact_string
from .privacy import PrivacyGuard
from .usage import identity

READ_BYTES = 8 << 20
LINE_BYTES = 1 << 20


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result if result.tzinfo and result <= datetime.now(timezone.utc) else None
    except (AttributeError, TypeError, ValueError):
        return None


class Recovery:
    def __init__(self, config, capture, coordinator):
        self.config, self.capture, self.coordinator = config, capture, coordinator
        self.lock = threading.RLock()
        self.after, self.requests, self.observations = [], [], []
        self.reader = None
        self.checkpoints = OrderedDict()
        self.follow = 0
        self.scope = identity(config)
        self.inflight = None

    def report(self):
        with self.lock:
            capture = self.capture()
            scope = identity(self.config)
            if scope != self.scope or not capture or not capture.get("tool_input"):
                self.scope = scope
                self.after = []
                self.inflight = None
                self.requests.clear()
                self.observations.clear()
                self.checkpoints.clear()
                if self.reader:
                    self.reader.close()
                    self.reader = None
                return None
            rows = []
            for item in self.observations:
                if not self.coordinator.project_metadata_allowed(item["product"], item["session_id"], item.get("parent_id")):
                    continue
                row = dict(item)
                limit = min(4096, capture.get("max_text_bytes") or 16384)
                if row.get("cwd") is not None and len(row.get("cwd", "").encode()) > limit:
                    row["cwd"] = None
                if capture.get("redact"):
                    for field in ("cwd", "parent_id"):
                        if isinstance(row.get(field), str):
                            _, reasons = redact_string(row[field])
                            if reasons:
                                if field == "cwd":
                                    row[field] = None
                                else:
                                    row.pop(field)
                if row.get("cwd") or row.get("parent_id") or row.get("cwd") is None:
                    rows.append(row)
            report = {"version": 1, "ready": not self.requests and self.reader is None,
                      "after": list(self.after), "observations": rows}
            self.inflight = (report, len(self.observations))
            return report

    def accept(self, sent, reply):
        if not sent or not isinstance(reply, dict) or reply.get("version") != 1:
            return
        with self.lock:
            # Only remove the prefix included in the successful heartbeat.
            # Rows suppressed by current permissions are discarded as well.
            if self.inflight is None or self.inflight[0] is not sent:
                return
            del self.observations[:self.inflight[1]]
            self.inflight = None
            if sent["ready"] and not self.requests and self.reader is None:
                requests = reply.get("requests", [])
                if not isinstance(requests, list) or len(requests) > 4:
                    return
                self.requests = [dict(row) for row in requests if isinstance(row, dict)
                    and row.get("product") in ("codex-cli", "claude-code")
                    and isinstance(row.get("session_id"), str)
                    and re.fullmatch(r"[A-Za-z0-9_-]{1,256}", row["session_id"])]
                self.after = ([self.requests[-1]["product"], self.requests[-1]["session_id"]]
                              if self.requests else [])

    def files(self, product, sid):
        from .integrations import configured_paths
        from .hook_runtime import registered_directories

        guard = PrivacyGuard()
        agent = "codex" if product == "codex-cli" else "claude"
        # Hook installation may record accounts absent from telemetry setup.
        roots = {path.parent for path in configured_paths(self.config, agent)}
        roots.update(path.parent for path in registered_directories(self.config))
        for home in sorted(roots):
            try:
                root = guard.check(home)
                patterns = ([f"sessions/*/*/*/rollout-*-{sid}.jsonl", f"archived_sessions/rollout-*-{sid}.jsonl"]
                            if agent == "codex" else [f"projects/*/{sid}.jsonl", f"projects/*/*/subagents/agent-{sid}.jsonl"])
                for pattern in patterns:
                    # Check intermediate directories before glob traverses them.
                    paths = [root]
                    for part in pattern.split("/"):
                        following = []
                        for parent in paths:
                            for path in parent.glob(part):
                                try:
                                    following.append(guard.check(path))
                                except OSError:
                                    continue
                        paths = following
                    yield from paths
            except (OSError, ValueError):
                continue

    def read(self, request):
        product, sid = request["product"], request["session_id"]
        if not self.coordinator.project_metadata_allowed(product, sid):
            return
        for path in self.files(product, sid):
            try:
                path = PrivacyGuard().check(path)
                stat = path.stat()
                key = (product, sid, str(path))
                state = self.checkpoints.get(key)
                if state is None or state["identity"] != (stat.st_dev, stat.st_ino) or stat.st_size < state["offset"]:
                    state = dict(identity=(stat.st_dev, stat.st_ino), offset=0, directory="", parent="", start=None,
                                 known=product == "claude-code", discarding=False)
                self.checkpoints[key] = state
                self.checkpoints.move_to_end(key)
                while len(self.checkpoints) > 512:
                    self.checkpoints.popitem(last=False)
                with path.open("rb") as source:
                    source.seek(state["offset"])
                    consumed = 0
                    while True:
                        line = source.readline(LINE_BYTES)
                        if not line:
                            break
                        consumed += len(line)
                        if not line.endswith(b"\n"):
                            if len(line) == LINE_BYTES:
                                state["discarding"] = True
                                state["offset"] = source.tell()
                            else:
                                break  # Retry an incomplete last record next time.
                        else:
                            state["offset"] = source.tell()
                            if state["discarding"]:
                                state["discarding"] = False
                            else:
                                try:
                                    record = json.loads(line)
                                except (ValueError, UnicodeError, RecursionError):
                                    record = None
                                if isinstance(record, dict):
                                    item = self.observation(record, product, sid, state)
                                    if item:
                                        yield item
                        if consumed >= READ_BYTES:
                            consumed = 0
                            yield None
                    state["scanned"] = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
            except (OSError, ValueError):
                continue

    def observation(self, record, product, sid, state):
        when = timestamp(record.get("timestamp"))
        if when is None:
            return None
        cwd, parent = "", state["parent"]
        if product == "codex-cli":
            payload = record.get("payload")
            if not isinstance(payload, dict):
                return None
            if record.get("type") == "session_meta":
                state["known"] = payload.get("id") == sid
                if not state["known"]:
                    return None
                state["start"] = when
                source = payload.get("source")
                if isinstance(source, dict):
                    subagent = source.get("subagent")
                    spawn = subagent.get("thread_spawn") if isinstance(subagent, dict) else None
                    parent = spawn.get("parent_thread_id", "") if isinstance(spawn, dict) else ""
            elif record.get("type") != "turn_context":
                return None
            if not state["known"] or (state["start"] and when < state["start"]):
                return None
            cwd = payload.get("cwd", "")
        else:
            if record.get("sessionId") != sid or record.get("type") not in ("user", "assistant"):
                return None
            cwd = record.get("cwd", "")
        if not isinstance(cwd, str) or len(cwd) > 4096 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in cwd):
            cwd = None
        if not isinstance(parent, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", parent) or parent == sid:
            parent = ""
        if cwd == "":
            cwd = state["directory"]
        if (cwd, parent) == (state["directory"], state["parent"]):
            return None
        state["directory"], state["parent"] = cwd, parent
        if not self.coordinator.project_metadata_allowed(product, sid, parent):
            return None
        return dict(product=product, session_id=sid, time=when.isoformat(), cwd=cwd, parent_id=parent)

    def step(self):
        with self.lock:
            capture = self.capture()
            if not capture or not capture.get("tool_input") or len(self.observations) >= 128:
                return
            if self.reader is None and self.requests:
                self.reader = self.read(self.requests.pop(0))
            elif self.reader is None and self.checkpoints:
                # Follow requested files even after their usage is attributed.
                # Checking one cached file per step bounds idle discovery work.
                keys = list(self.checkpoints)
                key = keys[self.follow % len(keys)]
                self.follow += 1
                stat = PrivacyGuard().check(key[2]).stat()
                current = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
                if current != self.checkpoints[key].get("scanned"):
                    self.reader = self.read({"product": key[0], "session_id": key[1]})
            if self.reader is not None:
                try:
                    item = next(self.reader)
                    if item:
                        self.observations.append(item)
                except StopIteration:
                    self.reader = None

    def run(self, stop):
        while not stop.is_set():
            try:
                self.step()
            except (OSError, ValueError, sqlite3.Error):
                pass
            stop.wait(0.1)
