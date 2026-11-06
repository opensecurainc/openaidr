"""Host sysstat collector and bounded file reader, using only the standard library.

The collector container reads host kernel counters and the host filesystem.
The API only reads its JSON output; sar and sadf use the same sysstat version.
"""

import json
import logging
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone

from . import host_metrics_history, service_cpu

INTERVAL = 60
MAX_SAMPLES = 1440
MAX_BYTES = 2 << 20
DEFAULT_PATH = "/var/lib/openaidr-host-metrics/history.json"
FIELDS = (
    "cpu_percent",
    "memory_percent",
    "disk_percent",
    "disk_read_bytes_per_second",
    "disk_write_bytes_per_second",
)
CAPACITY_FIELDS = (
    "cpu_count",
    "memory_used_bytes",
    "memory_total_bytes",
    "disk_used_bytes",
    "disk_total_bytes",
)
RANGES = {"5m": 5 / 60, "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
DISK_PATH = re.compile(r"/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*)?")


def valid_disk_path(value):
    # A normalized absolute host path, such as / or a dedicated data mount.
    return (
        isinstance(value, str)
        and len(value) <= 255
        and DISK_PATH.fullmatch(value) is not None
        and os.path.normpath(value) == value
    )


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def number(value, maximum=None):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid metric")
    if maximum is not None and value > maximum:
        raise ValueError("metric exceeds its range")
    return round(value, 2)


def capacity_fields(row):
    # Older collectors did not record capacity. Keep those samples intact.
    if not any(key in row for key in CAPACITY_FIELDS):
        return {}
    result = {key: row[key] for key in CAPACITY_FIELDS}
    for key, value in result.items():
        minimum = 0 if key.endswith("_used_bytes") else 1
        if type(value) is not int or not minimum <= value <= 2**53 - 1:
            raise ValueError("invalid host capacity")
    for resource in ("memory", "disk"):
        if result[f"{resource}_used_bytes"] > result[f"{resource}_total_bytes"]:
            raise ValueError("host usage exceeds capacity")
    return result


def service_fields(row):
    if "service_cpu_percent" not in row:
        return {}
    values = row["service_cpu_percent"]
    if not isinstance(values, dict) or set(values) != set(service_cpu.SERVICES):
        raise ValueError("invalid service CPU metrics")
    if "cpu_count" not in row:
        raise ValueError("service CPU metrics require host capacity")
    return {"service_cpu_percent": {
        name: None if value is None else number(value, 100)
        for name, value in values.items()
    }}


def filesystem_fields(row):
    result = {}
    if "disk_is_root" in row:
        if type(row["disk_is_root"]) is not bool:
            raise ValueError("invalid filesystem identity")
        result["disk_is_root"] = row["disk_is_root"]
    root_fields = ("root_disk_percent", "root_disk_used_bytes",
                   "root_disk_total_bytes", "root_disk_available_bytes")
    if any(key in row for key in root_fields):
        result.update({key: row[key] for key in root_fields})
        result["root_disk_percent"] = number(result["root_disk_percent"], 100)
    if "disk_available_bytes" in row:
        result["disk_available_bytes"] = row["disk_available_bytes"]
    for resource in ("disk", "root_disk"):
        available = f"{resource}_available_bytes"
        if available not in result:
            continue
        used, total = (row[f"{resource}_{kind}_bytes"] for kind in ("used", "total"))
        for value, minimum in ((used, 0), (total, 1), (result[available], 0)):
            if type(value) is not int or not minimum <= value <= 2**53 - 1:
                raise ValueError("invalid filesystem capacity")
        if used + result[available] > total:
            raise ValueError("filesystem usage exceeds capacity")
    return result


def load_history(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("metrics history is too large")
    data = json.loads(raw)
    if (
        data["version"] != 1
        or data["interval_seconds"] != INTERVAL
        or not isinstance(data["hostname"], str)
        or not 0 < len(data["hostname"]) <= 255
        or not valid_disk_path(data["disk_path"])
        or not isinstance(data["samples"], list)
        or len(data["samples"]) > MAX_SAMPLES
    ):
        raise ValueError("invalid metrics history")
    samples = []
    previous = None
    for row in data["samples"]:
        when = timestamp(row["time"])
        if previous and when <= previous:
            raise ValueError("metrics must be in time order")
        samples.append(
            {
                "time": when.isoformat(),
                **{
                    key: number(row[key], 100 if key.endswith("percent") else None)
                    for key in FIELDS
                },
                **capacity_fields(row),
                **filesystem_fields(row),
                **service_fields(row),
            }
        )
        previous = when
    return dict(
        version=1,
        hostname=data["hostname"],
        disk_path=data["disk_path"],
        interval_seconds=INTERVAL,
        samples=samples,
    )


def normalize(report, disk, memory_total_bytes, root_disk, disk_is_root):
    (host,) = report["sysstat"]["hosts"]
    (sample,) = host["statistics"]
    clock = sample["timestamp"]
    if clock["tz"] != "UTC":
        raise ValueError("sysstat must report UTC timestamps")
    cpu = next(item for item in sample["cpu-load"] if item["cpu"] == "all")
    io = sample["io"]
    return host["nodename"], {
        "time": timestamp(clock["date"] + "T" + clock["time"] + "+00:00").isoformat(),
        # Non-idle includes I/O wait and steal, matching sar's CPU accounting.
        "cpu_percent": number(100 - number(cpu["idle"], 100), 100),
        "memory_percent": number(sample["memory"]["memused-percent"], 100),
        "disk_percent": number(disk.used / disk.total * 100, 100),
        "disk_available_bytes": disk.free,
        **filesystem_fields({
            "root_disk_percent": root_disk.used / root_disk.total * 100,
            "root_disk_used_bytes": root_disk.used,
            "root_disk_total_bytes": root_disk.total,
            "root_disk_available_bytes": root_disk.free,
            "disk_is_root": disk_is_root,
        }),
        **capacity_fields(
            {
                "cpu_count": host["number-of-cpus"],
                "memory_used_bytes": sample["memory"]["memused"] * 1024,
                "memory_total_bytes": memory_total_bytes,
                "disk_used_bytes": disk.used,
                "disk_total_bytes": disk.total,
            }
        ),
        # sar -b reports 512-byte blocks per second, regardless of sector size.
        "disk_read_bytes_per_second": number(io["io-reads"]["bread"] * 512),
        "disk_write_bytes_per_second": number(io["io-writes"]["bwrtn"] * 512),
    }


def host_disk_path(host_root, configured=None):
    if configured is not None:
        # Deployments whose data lives on a dedicated disk name that mount.
        if (
            not valid_disk_path(configured)
            or not (Path(host_root) / configured.lstrip("/")).is_dir()
        ):
            raise ValueError("OPENAIDR_HOST_DISK_PATH must name a host directory")
        return configured
    try:
        release = shlex.split(
            (Path(host_root) / "etc/os-release").read_text(), comments=True
        )
    except FileNotFoundError:
        return "/"
    # Docker Desktop's root overlay is RAM-backed; persistent data lives here.
    return "/var/lib" if "PRETTY_NAME=Docker Desktop" in release else "/"


def collect_sample(interval=INTERVAL, host_root="/host-root"):
    before = service_cpu.snapshot(host_root)
    started = time.monotonic()
    env = {**os.environ, "LC_ALL": "C", "TZ": "UTC", "S_TIME_DEF_TIME": "UTC"}
    with tempfile.TemporaryDirectory(prefix="openaidr-sysstat-") as directory:
        binary = str(Path(directory) / "sample.sa")
        subprocess.run(
            ["sar", "-u", "-r", "-b", "-o", binary, str(interval), "1"],
            env=env,
            check=True,
            timeout=interval + 15,
            stdout=subprocess.DEVNULL,
        )
        after = service_cpu.snapshot(host_root)
        elapsed = time.monotonic() - started
        result = subprocess.run(
            ["sadf", "-j", binary, "--", "-u", "-r", "-b"],
            env=env,
            check=True,
            timeout=10,
            capture_output=True,
        )
    memory_total_bytes = next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemTotal:")
    )
    disk_path = host_disk_path(host_root, os.environ.get("OPENAIDR_HOST_DISK_PATH"))
    root = Path(host_root)
    data = root / disk_path.lstrip("/")
    disk_is_root = data.stat().st_dev == root.stat().st_dev
    disk = shutil.disk_usage(data)
    host, sample = normalize(
        json.loads(result.stdout),
        disk,
        memory_total_bytes,
        root_disk=disk if disk_is_root else shutil.disk_usage(root),
        disk_is_root=disk_is_root,
    )
    sample["service_cpu_percent"] = service_cpu.percentages(
        before, after, elapsed, sample["cpu_count"],
    )
    return host, sample, disk_path


def save_sample(path, hostname, sample, disk_path="/"):
    path = Path(path)
    try:
        history = load_history(path)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        history = {"hostname": hostname, "disk_path": disk_path, "samples": []}
    when = timestamp(sample["time"])
    samples = [
        row
        for row in history["samples"]
        if history["hostname"] == hostname
        and history["disk_path"] == disk_path
        and when - timedelta(hours=24) < timestamp(row["time"]) < when
    ]
    payload = dict(
        version=1,
        hostname=hostname,
        disk_path=disk_path,
        interval_seconds=INTERVAL,
        samples=(samples + [sample])[-MAX_SAMPLES:],
    )
    # Replace within the same directory: readers see either complete version.
    temporary = path.with_suffix(".tmp")
    try:
        with temporary.open("w") as stream:
            json.dump(payload, stream, allow_nan=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    try:
        host_metrics_history.record(path, payload)
    except (OSError, sqlite3.Error):
        logging.getLogger(__name__).exception("Could not archive host metrics; recent history is retained")


def read_metrics(path, range_name="24h", now=None):
    now = now or datetime.now(timezone.utc)
    result = dict(
        status="disabled",
        message="Host monitoring is not configured for this deployment.",
        range=range_name,
        interval_seconds=INTERVAL,
        hostname=None,
        disk_path="/",
        last_sample_at=None,
        samples=[],
    )
    if not path:
        return result
    try:
        history = load_history(path)
        if any(
            timestamp(row["time"]) > now + timedelta(seconds=INTERVAL)
            for row in history["samples"]
        ):
            raise ValueError("metrics timestamp is in the future")
    except FileNotFoundError:
        return {
            **result,
            "status": "waiting",
            "message": "Waiting for the first host sample.",
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {
            **result,
            "status": "unavailable",
            "message": "Host metrics could not be read.",
        }
    samples = history["samples"]
    last = samples[-1]["time"] if samples else None
    status = (
        "waiting"
        if not last
        else "stale"
        if now - timestamp(last) > timedelta(seconds=3 * INTERVAL)
        else "ok"
    )
    selected = [
        row for row in samples
        if now - timedelta(hours=RANGES[range_name]) <= timestamp(row["time"]) <= now
    ]
    extra = {}
    if range_name in host_metrics_history.RESOLUTION:
        interval = host_metrics_history.RESOLUTION[range_name]
        latest = selected[-1] if selected else None
        try:
            selected, summary = host_metrics_history.aggregate(
                host_metrics_history.samples(
                    path, history, (now - timedelta(hours=RANGES[range_name])).timestamp(), now.timestamp(),
                ), interval, FIELDS, service_cpu.SERVICES, optional_fields=("root_disk_percent",),
            )
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
            return {**result, "status": "unavailable", "message": "Host metrics archive could not be read."}
        extra = dict(interval_seconds=interval, service_cpu_summary=summary,
                     latest_sample=latest)
    return {
        **result,
        "status": status,
        "message": {
            "waiting": "Waiting for the first host sample.",
            "stale": "Host metrics are delayed. Showing the last collected samples.",
            "ok": "",
        }[status],
        "hostname": history["hostname"],
        "disk_path": history["disk_path"],
        "last_sample_at": last,
        "samples": selected,
        **extra,
    }


if __name__ == "__main__":
    while True:
        host, row, disk_path = collect_sample()
        save_sample(DEFAULT_PATH, host, row, disk_path)
