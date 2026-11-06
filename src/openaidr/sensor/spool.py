"""Thread-safe disk queue, retaining compatibility with existing JSONL spools."""

import json
import threading
import time
from pathlib import Path
from openaidr.core.files import atomic_write


class Spool:
    def __init__(self, directory, max_segment_bytes=4 << 20, max_total_bytes=512 << 20):
        self.path = Path(directory)
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_segment, self.max_total = max_segment_bytes, max_total_bytes
        self.lock = threading.RLock()
        self.dropped, self.closed = 0, False
        try:
            self.cursor = json.loads((self.path / "cursor.json").read_text())
        except (OSError, ValueError):
            self.cursor = {}
        if (
            self.cursor.get("segment")
            and not (self.path / self.cursor["segment"]).exists()
        ):
            self.cursor = {}
        self.current = None
        segments = self.segments()
        self.last_name = segments[-1].name if segments else ""

    def segments(self):
        return sorted(self.path.glob("*.jsonl"))

    def append(self, event):
        line = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        with self.lock:
            if self.closed:
                raise ValueError("spool is closed")
            if self.current is None or self.current.stat().st_size >= self.max_segment:
                stamp = time.time_ns()
                name = f"{stamp:020d}.jsonl"
                if name <= self.last_name:
                    stamp = int(self.last_name.removesuffix(".jsonl")) + 1
                    name = f"{stamp:020d}.jsonl"
                self.last_name = name
                self.current = self.path / name
                self.current.touch(mode=0o600, exist_ok=False)
            with self.current.open("ab") as f:
                f.write(line)
                f.flush()
                import os

                os.fsync(f.fileno())
            segments = self.segments()
            total = sum(p.stat().st_size for p in segments)
            for p in segments[:-1]:
                if total <= self.max_total:
                    break
                size = p.stat().st_size
                with p.open("rb") as f:
                    if p.name == self.cursor.get("segment"):
                        f.seek(self.cursor.get("offset", 0))
                    self.dropped += sum(1 for _ in f)
                p.unlink()
                total -= size
                if p.name == self.cursor.get("segment"):
                    self.cursor = {}

    def read(self, limit=100):
        with self.lock:
            events, cursor = [], None
            for p in self.segments():
                if p.name < self.cursor.get("segment", ""):
                    continue
                with p.open("rb") as f:
                    if p.name == self.cursor.get("segment"):
                        f.seek(self.cursor.get("offset", 0))
                    while len(events) < limit:
                        line = f.readline()
                        if not line or not line.endswith(b"\n"):
                            break
                        cursor = {"segment": p.name, "offset": f.tell()}
                        try:
                            events.append(json.loads(line))
                        except ValueError:
                            continue
                if len(events) >= limit:
                    break
            return {"events": events, "cursor": cursor} if cursor else None

    def ack(self, batch):
        with self.lock:
            cursor = batch["cursor"]
            if cursor is None:
                return
            previous = (self.cursor.get("segment", ""), self.cursor.get("offset", 0))
            incoming = (cursor["segment"], cursor["offset"])
            if incoming <= previous:
                return
            # A batch whose segment was dropped by the capacity limit cannot
            # move the cursor back into deleted queue data.
            if not (self.path / cursor["segment"]).exists():
                return
            atomic_write(self.path / "cursor.json", json.dumps(cursor))
            self.cursor = cursor
            for p in self.segments():
                if p.name < cursor["segment"]:
                    p.unlink()

    @property
    def depth(self):
        with self.lock:
            count = 0
            for path in self.segments():
                if path.name < self.cursor.get("segment", ""):
                    continue
                with path.open("rb") as stream:
                    if path.name == self.cursor.get("segment"):
                        stream.seek(self.cursor.get("offset", 0))
                    for line in stream:
                        if line.endswith(b"\n"):
                            count += 1
            return count

    def close(self):
        self.closed = True
