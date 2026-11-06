"""Read Docker cgroup v2 CPU counters without a Docker socket or process arguments."""

import os
from pathlib import Path
import re

SERVICES = ("postgres", "server", "dashboard")
CONTAINER = re.compile(r"^(.*(?:/docker/[0-9a-f]{64}|/docker-[0-9a-f]{64}\.scope))(?:/.*)?$")


def snapshot(host_root="/host-root"):
    root = Path(host_root)
    groups = {name: {} for name in SERVICES}
    try:
        if not (root / "sys/fs/cgroup/cgroup.controllers").is_file():
            return None
        paths = {}
        with os.scandir(root / "proc") as entries:
            for index, entry in enumerate(entries):
                if index >= 16384:
                    return None
                if not entry.name.isdecimal():
                    continue
                process = Path(entry.path)
                try:
                    name = (process / "comm").read_text().strip()
                    service = ("postgres" if name == "postgres" else
                               "server" if name == "openaidr-server" else
                               "dashboard" if name.startswith("next-server") else None)
                    if service is None:
                        continue
                    group = next((line[3:] for line in (process / "cgroup").read_text().splitlines()
                                  if line.startswith("0::")), "")
                    if ".." in Path(group).parts:
                        return None
                    match = CONTAINER.fullmatch(group)
                    if not match:
                        continue
                    path = match[1]
                    if path in paths and paths[path] != service:
                        return None
                    paths[path] = service
                except (FileNotFoundError, ProcessLookupError):
                    continue
        for path, service in paths.items():
            counter = root / "sys/fs/cgroup" / path.lstrip("/") / "cpu.stat"
            fields = dict(line.split() for line in counter.read_text().splitlines())
            usage = int(fields["usage_usec"])
            if usage < 0:
                return None
            groups[service][path] = usage
        return groups
    except (OSError, ValueError, KeyError):
        return None


def percentages(before, after, seconds, cpu_count):
    result = dict.fromkeys(SERVICES)
    if before is None or after is None or seconds <= 0 or cpu_count <= 0:
        return result
    for service in SERVICES:
        start, end = before[service], after[service]
        # A changed container set or a reset counter is a gap, never a zero.
        if not start or start.keys() != end.keys():
            continue
        deltas = [end[path] - value for path, value in start.items()]
        if min(deltas) < 0:
            continue
        percent = sum(deltas) / (seconds * 1_000_000 * cpu_count) * 100
        # Counter reads and the wall-clock boundary are not atomic. Preserve
        # saturated samples when collection timing puts them just over 100%.
        if percent <= 105:
            result[service] = round(min(percent, 100), 2)
    return result
