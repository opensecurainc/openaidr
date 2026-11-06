"""Bounded, local host history. The API opens the collector's archive read-only."""

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

RETENTION_SECONDS = 30 * 86400
MAX_SAMPLES = RETENTION_SECONDS // 60
RESOLUTION = {"7d": 600, "30d": 1800}


def record(path, history):
    path = Path(path).with_suffix(".sqlite3")
    with closing(sqlite3.connect(path, timeout=1)) as db, db:
        # Rollback journals permit readers on the API's read-only volume mount.
        db.execute("PRAGMA cache_size = -1024")
        db.execute("CREATE TABLE IF NOT EXISTS source (hostname TEXT, disk_path TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS samples (at REAL PRIMARY KEY, payload TEXT NOT NULL)")
        source = (history["hostname"], history["disk_path"])
        if db.execute("SELECT hostname, disk_path FROM source").fetchone() != source:
            db.execute("DELETE FROM samples")
            db.execute("DELETE FROM source")
            db.execute("INSERT INTO source VALUES (?, ?)", source)
        last = db.execute("SELECT MAX(at) FROM samples").fetchone()[0]
        rows = history["samples"]
        latest = datetime.fromisoformat(rows[-1]["time"]).timestamp()
        # Clock rollback replaces future samples, as the recent JSON history does.
        db.execute("DELETE FROM samples WHERE at > ? OR at <= ?", (latest, latest - RETENTION_SECONDS))
        db.executemany("INSERT OR REPLACE INTO samples VALUES (?, ?)", (
            (at, json.dumps(row, allow_nan=False, separators=(",", ":")))
            for row in rows
            if (at := datetime.fromisoformat(row["time"]).timestamp()) >= min(last or 0, latest)
        ))
        db.execute("DELETE FROM samples WHERE at < (SELECT at FROM samples ORDER BY at DESC LIMIT 1 OFFSET ?)", (MAX_SAMPLES - 1,))
    path.chmod(0o644)


def samples(path, history, start, end):
    """Stream older rows, then use the recent file to cover interrupted writes."""
    path = Path(path).with_suffix(".sqlite3")
    recent = history["samples"]
    boundary = datetime.fromisoformat(recent[0]["time"]).timestamp() if recent else end
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
            db.execute("PRAGMA cache_size = -1024")
            db.execute("BEGIN")
            source = db.execute("SELECT hostname, disk_path FROM source").fetchone()
            if source == (history["hostname"], history["disk_path"]):
                for at, payload in db.execute(
                    "SELECT at, payload FROM samples WHERE at >= ? AND at <= ? AND at < ? ORDER BY at LIMIT ?",
                    (start, end, boundary, MAX_SAMPLES),
                ):
                    yield at, json.loads(payload)
    for row in recent:
        at = datetime.fromisoformat(row["time"]).timestamp()
        if start <= at <= end:
            yield at, row


def aggregate(rows, interval, fields, services, optional_fields=()):
    points = []
    summaries = {name: dict(count=0, percent=0, cores=0) for name in services}
    total = 0
    bucket = None
    previous = None
    point = None
    count = 0

    def finish():
        if point is None:
            return
        for key in fields:
            point[key] /= count
        for key in optional_fields:
            if point[key] is not None:
                point[key] /= count
        for name, value in point["service_cpu_percent"].items():
            if value is not None:
                point["service_cpu_percent"][name] /= count
        points.append(point)

    for at, row in rows:
        current = int(at // interval)
        if current != bucket:
            finish()
            bucket, count = current, 0
            point = {key: 0 for key in fields}
            point.update({key: 0 for key in optional_fields})
            point["service_cpu_percent"] = {name: 0 for name in services}
        point["time"] = datetime.fromtimestamp(at, timezone.utc).isoformat()
        if previous is not None and at - previous > 90:
            point["gap_before"] = True
        previous = at
        count += 1
        total += 1
        for key in fields:
            point[key] += row[key]
        for key in optional_fields:
            value = row.get(key)
            if value is None:
                point[key] = None
            elif point[key] is not None:
                point[key] += value
        for name in services:
            value = row.get("service_cpu_percent", {}).get(name)
            if value is None:
                point["service_cpu_percent"][name] = None
            else:
                summary = summaries[name]
                summary["count"] += 1
                summary["percent"] += value
                summary["cores"] += value * row["cpu_count"] / 100
                if point["service_cpu_percent"][name] is not None:
                    point["service_cpu_percent"][name] += value
    finish()
    for summary in summaries.values():
        for key in ("percent", "cores"):
            summary[key] = summary[key] / summary["count"] if summary["count"] else None
    return points, {"total_samples": total, "services": summaries}
