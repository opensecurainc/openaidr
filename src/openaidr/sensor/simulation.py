"""One development process representing 100 enrolled devices on a local test tenant."""

import asyncio
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
from platform import machine
import re
import signal
import sys
import threading
import time
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5

import httpx
import yaml

from openaidr.core.event import new_id, now
from openaidr.core.telemetry import encode_export
from .config import Config
from openaidr.core.files import atomic_write
from openaidr.core.enrollment import validate_server_url
from .tls import verified_context

DEVICES = 100
PRODUCTS = ("claude-code", "codex-cli")


def configuration(source):
    if os.environ.get("OPENAIDR_DEVICE_SIMULATION") != "1" or os.name == "nt":
        raise ValueError(
            "Device simulation is available only in development builds on macOS and Linux."
        )
    path = Path(source["data_dir"]) / "simulation.yaml"
    if not path.is_file():
        raise ValueError(
            "Configure a separate local test workspace in simulation.yaml before starting."
        )
    if path.stat().st_mode & 0o077:
        raise ValueError("Protect simulation.yaml with file permissions 600.")
    with path.open() as stream:
        value = yaml.safe_load(stream.read(65537))
    if not isinstance(value, dict) or value.get("enabled") is not True:
        raise ValueError("Enable the local test workspace in simulation.yaml.")
    origin = validate_server_url(value.get("server_url", ""))
    parsed = urlsplit(origin)
    try:
        loopback = (
            parsed.hostname == "localhost"
            or ipaddress.ip_address(parsed.hostname).is_loopback
        )
    except ValueError:
        loopback = False
    if (
        not loopback
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise ValueError("Simulation requires a loopback server origin.")
    tenant = str(UUID(value.get("tenant_id", "")))
    if tenant == source.get("tenant_id"):
        raise ValueError(
            "Choose a test tenant separate from this device's organization."
        )
    token = value.get("enrollment_token", "")
    if not isinstance(token, str) or not token.startswith("oaet_") or len(token) > 1024:
        raise ValueError(
            "Configure a test enrollment token with at least 100 available uses."
        )
    return {
        "server_url": origin.rstrip("/"),
        "tenant_id": tenant,
        "enrollment_token": token,
        "ca_cert": value.get("ca_cert"),
        "name": str(value.get("name") or "Local Dev")[:80],
    }


def status(source):
    if os.environ.get("OPENAIDR_DEVICE_SIMULATION") != "1" or os.name == "nt":
        return {"enabled": False}
    result = dict(
        enabled=True,
        configured=False,
        state="stopped",
        devices=DEVICES,
        enrolled=0,
        records_sent=0,
        inventories_sent=0,
        errors=0,
        destination="",
        error="",
    )
    try:
        options = configuration(source)
        result.update(configured=True, destination=options["name"])
    except (ValueError, OSError, TypeError, AttributeError, yaml.YAMLError):
        result["error"] = (
            "Configure a separate local test workspace in simulation.yaml."
        )
    return result


def read_json(path, limit=16 << 20):
    with path.open() as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Simulation data exceeds its size limit.")
    return json.loads(content)


def baseline(source):
    """Use the existing collector cache without scanning or changing the live sensor."""
    snapshots = {}
    for filename, endpoint in (
        ("component-inventory.json", "inventory/snapshots"),
        ("application-inventory.json", "inventory/applications"),
    ):
        path = Path(source["data_dir"]) / filename
        if not path.exists():
            continue
        saved = read_json(path, 8 << 20)
        if saved.get("identity", [])[:2] != [
            source.get("server_url"),
            source.get("sensor_id"),
        ]:
            continue
        snapshot = saved.get("snapshot", {})
        # macOS has one active collector; an old native cache is retained for rollback.
        if endpoint.endswith("applications") and snapshot.get("platform") == "darwin":
            continue
        if snapshot.get("schema_version") == 1:
            snapshots[endpoint] = snapshot
    if not snapshots:
        raise ValueError(
            "Wait for this device's first inventory scan before starting simulation."
        )
    return snapshots


def products(index):
    return (PRODUCTS[index % 2],) if index % 3 else PRODUCTS


def inventory(snapshot, fleet_id, index):
    """Stable subsets, with references removed together with their endpoints."""
    username = f"sim-user-{index + 1:03d}"

    def transform(value):
        if isinstance(value, dict):
            return {
                key: username if key == "user" else transform(item)
                for key, item in value.items()
                if key != "sensor_id"
            }
        if isinstance(value, list):
            return [transform(item) for item in value]
        if isinstance(value, str):
            value = re.sub(r"(/Users/|/home/)[^/\s]+", lambda m: m[1] + username, value)
            return re.sub(
                r"(?i)([A-Z]:[\\/]Users[\\/])[^\\/\s]+",
                lambda m: m[1] + username,
                value,
            )
        return value

    result = transform(snapshot)
    result["collected_at"] = now()

    def keep(item):
        name = (item.get("identifier", "") + " " + item.get("name", "")).lower()
        for marker, product in (("claude", "claude-code"), ("codex", "codex-cli")):
            if marker in name:
                return product in products(index)
        key = json.dumps(
            [fleet_id, index, item.get("key", item.get("identifier")), item.get("path")]
        )
        return hashlib.sha256(key.encode()).digest()[0] >= 64

    if "applications" in result:
        result["applications"] = [item for item in result["applications"] if keep(item)]
        for source in result["sources"]:
            source["message"] = "Synthetic inventory subset"
    if "roots" in result:
        references = set()
        for root in result["roots"]:
            root["message"] = "Synthetic inventory subset"
            root["components"] = [item for item in root["components"] if keep(item)]
            references.update(
                (root["source"], root["root"], item["key"])
                for item in root["components"]
            )
        for root in result["roots"]:
            root["relationships"] = [
                edge
                for edge in root["relationships"]
                if all(
                    tuple(edge[end][key] for key in ("source", "root", "key"))
                    in references
                    for end in ("from", "to")
                )
            ]
    return result


def activity(fleet_id, index, turn, run_id, platform):
    product = products(index)[turn % len(products(index))]
    user, host = f"sim-user-{index + 1:03d}", f"sim-device-{index + 1:03d}"
    session = str(uuid5(UUID(fleet_id), f"{index}/{run_id}/{product}/{turn // 12}"))
    call = f"sim-{session}-{turn}"
    cwd = (
        f"/Users/{user}/projects/sample-{index % 4}"
        if platform == "darwin"
        else f"/home/{user}/projects/sample-{index % 4}"
    )
    model = "gpt-6.1-sol" if product == "codex-cli" else "claude-opus-5-5"
    common = dict(
        schema_version=1,
        time=now(),
        agent={"product": product, "version": "simulation", "model": model},
        host={"hostname": host, "user": user, "os": platform, "arch": machine()},
        session={"id": session, "cwd": cwd},
        source={"collector": "hook", "synthetic": True, "emulator_run_id": run_id},
    )
    events = [
        dict(copy.deepcopy(common), id=new_id(), kind=kind, **details)
        for kind, details in (
            ("prompt", {"text": "Synthetic task: inspect the sample project."}),
            (
                "command",
                {
                    "command": {"text": "git status --short", "cwd": cwd},
                    "tool": {"name": "Bash", "call_id": call},
                },
            ),
            (
                "tool.result",
                {
                    "tool": {
                        "name": "Bash",
                        "call_id": call,
                        "output": "Synthetic result: working tree clean.",
                    }
                },
            ),
            ("response", {"text": "Synthetic response: the sample project is clean."}),
        )
    ]

    def attrs(values):
        return [
            {
                "key": key,
                "value": {"boolValue": value}
                if isinstance(value, bool)
                else {"stringValue": str(value)},
            }
            for key, value in values.items()
        ]

    event = "codex.sse_event" if product == "codex-cli" else "claude_code.api_request"
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": attrs(
                        {
                            "service.name": product,
                            "service.version": "simulation",
                            "host.name": host,
                            "os.type": platform,
                            "user.name": user,
                            "openaidr.demo": True,
                            "openaidr.demo.run_id": run_id,
                        }
                    )
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "openaidr.simulation"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "body": {"stringValue": event},
                                "attributes": attrs(
                                    {
                                        "event.name": event,
                                        "session.id": session,
                                        "conversation.id": session,
                                        "user.name": user,
                                        "model": model,
                                        "cwd": cwd,
                                        "openaidr.demo": True,
                                        "input_token_count": 800 + index * 13,
                                        "output_token_count": 100 + turn % 100,
                                        "input_tokens": 800 + index * 13,
                                        "output_tokens": 100 + turn % 100,
                                        "cost_usd": "0.003",
                                        "duration_ms": 500 + index * 7,
                                        "success": True,
                                        "event.kind": "response.completed",
                                    }
                                ),
                            }
                        ],
                    }
                ],
            }
        ]
    }
    return events, encode_export("logs", payload, "application/json")


class Stopped(Exception):
    pass


class Fleet:
    def __init__(self, source, report=lambda _: None):
        self.options = configuration(source)
        self.directory = Path(source["data_dir"]) / "simulation"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "fleet.json"
        identity = [self.options["server_url"], self.options["tenant_id"]]
        if self.path.exists():
            self.saved = read_json(self.path)
            if self.saved.get("identity") != identity:
                raise ValueError(
                    "The saved simulation belongs to another test workspace."
                )
        else:
            self.saved = dict(
                identity=identity,
                id=str(uuid4()),
                baseline=baseline(source),
                devices={},
            )
            self.save()
        self.stop = threading.Event()
        self.report = report
        self.run_id = str(uuid4())
        self.summary = dict(
            status(source), state="starting", enrolled=len(self.saved["devices"])
        )
        self.slots = asyncio.Semaphore(8)

    def save(self):
        atomic_write(self.path, json.dumps(self.saved, ensure_ascii=True))

    async def wait(self, seconds):
        deadline = time.monotonic() + seconds
        while not self.stop.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(min(0.2, max(0, deadline - time.monotonic())))

    async def post(self, client, path, data, device=None, batch=None, retry=True):
        headers = {"Authorization": "Bearer " + device["token"]} if device else {}
        if batch:
            headers.update(
                {"Content-Type": "application/json", "X-OpenAIDR-Batch-Id": batch}
            )
        for attempt in range(3 if retry else 1):
            if self.stop.is_set():
                raise Stopped()
            try:
                async with self.slots:
                    if self.stop.is_set():
                        raise Stopped()
                    response = await client.post(
                        path,
                        headers=headers,
                        **({"content": data} if batch else {"json": data}),
                    )
                if response.status_code < 400:
                    return response.json()
                self.summary["errors"] += 1
                if (
                    response.status_code not in (429, 502, 503, 504)
                    or attempt == 2
                    or not retry
                ):
                    raise ValueError(
                        f"Simulation request failed (HTTP {response.status_code}). Check the test workspace."
                    )
            except httpx.TransportError:
                self.summary["errors"] += 1
                if attempt == 2 or not retry:
                    raise ValueError("Cannot reach the simulation workspace.") from None
            await self.wait(0.5 * 2**attempt)
        raise Stopped()

    async def enroll(self, client, index):
        device = self.saved["devices"].get(str(index))
        if not device:
            enrolled = await self.post(
                client,
                "/ingest/v1/enroll",
                dict(
                    enrollment_token=self.options["enrollment_token"],
                    hostname=f"sim-device-{index + 1:03d}",
                    user=f"sim-user-{index + 1:03d}",
                    os=next(iter(self.saved["baseline"].values()))["platform"],
                    arch=machine(),
                    host_kind="workstation",
                    label=f"Simulation {self.saved['id'][:8]} / {index + 1:03d}",
                    sensor_version="simulation",
                ),
                retry=False,
            )
            if enrolled.get("tenant", {}).get("id") != self.options["tenant_id"]:
                raise ValueError(
                    "The enrollment token belongs to a different tenant. No simulated data was sent."
                )
            device = dict(
                id=enrolled["sensor_id"],
                token=enrolled["sensor_token"],
                interval=enrolled.get("config", {}).get("heartbeat_interval_s", 30),
            )
            self.saved["devices"][str(index)] = device
            self.save()
            self.summary["enrolled"] = len(self.saved["devices"])
        return device

    async def device(self, client, index):
        snapshots = self.saved["baseline"]
        platform = next(iter(snapshots.values()))["platform"]
        device = await self.enroll(client, index)
        for endpoint, snapshot in snapshots.items():
            await self.post(
                client,
                "/ingest/v1/" + endpoint,
                inventory(snapshot, self.saved["id"], index),
                device,
            )
            self.summary["inventories_sent"] += 1
        await self.wait(index / 20)
        heartbeat_at = activity_at = 0
        turn = 0
        while not self.stop.is_set():
            clock = time.monotonic()
            if clock >= heartbeat_at:
                reply = await self.post(
                    client,
                    "/ingest/v1/heartbeat",
                    dict(
                        sensor_version="simulation",
                        queue_depth=0,
                        telemetry_queue_depth=0,
                        collectors={},
                        hook_installed=False,
                        policy_version=0,
                    ),
                    device,
                )
                if reply.get("disabled"):
                    raise ValueError(
                        "A simulated device was disabled. Stop and inspect the test workspace."
                    )
                heartbeat_at = clock + max(5, min(300, device["interval"]))
            if clock >= activity_at:
                events, usage = activity(
                    self.saved["id"], index, turn, self.run_id, platform
                )
                ack = await self.post(
                    client,
                    "/ingest/v1/events",
                    {"sensor_id": device["id"], "events": events},
                    device,
                )
                if ack.get("rejected") or ack.get("accepted", 0) + ack.get(
                    "duplicates", 0
                ) != len(events):
                    raise ValueError("The test workspace rejected simulated activity.")
                self.summary["records_sent"] += len(events)
                ack = await self.post(
                    client, "/otlp/v1/logs", usage, device, str(uuid4())
                )
                if int(ack.get("partialSuccess", {}).get("rejectedLogRecords", 0)):
                    raise ValueError("The test workspace rejected simulated telemetry.")
                self.summary["records_sent"] += 1
                turn += 1
                activity_at = clock + (120 if index % 4 == 0 else 8 + index % 23)
            await self.wait(0.5)

    async def run(self):
        async with httpx.AsyncClient(
            base_url=self.options["server_url"],
            verify=verified_context(self.options.get("ca_cert")),
            timeout=5,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            self.report(dict(self.summary))
            missing = next(
                (
                    index
                    for index in range(DEVICES)
                    if str(index) not in self.saved["devices"]
                ),
                None,
            )
            if missing is not None:
                # Preview requires an expiring token with a finite use limit. Check
                # one new enrollment before allowing the remaining fleet to enroll.
                try:
                    await self.enroll(client, missing)
                except Stopped:
                    return
            tasks = [
                asyncio.create_task(self.device(client, index))
                for index in range(DEVICES)
            ]
            try:
                while not self.stop.is_set():
                    for task in tasks:
                        if task.done():
                            task.result()
                    if self.summary["enrolled"] == DEVICES:
                        self.summary["state"] = "running"
                    self.report(dict(self.summary))
                    await self.wait(1)
            except Exception:
                self.stop.set()
                raise
            finally:
                self.stop.set()
                await asyncio.gather(*tasks, return_exceptions=True)


def main():
    source = Config.load()
    result = status(source)
    fleet = None

    def report(value):
        try:
            print(json.dumps(value), flush=True)
        except BrokenPipeError:
            if fleet:
                fleet.stop.set()

    try:
        configuration(source)
        import fcntl

        directory = Path(source["data_dir"]) / "simulation"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (directory / "run.lock").open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("A device simulation is already running.") from None
            fleet = Fleet(source, report)
            for number in (signal.SIGINT, signal.SIGTERM):
                signal.signal(number, lambda *_: fleet.stop.set())
            threading.Thread(
                target=lambda: (sys.stdin.read(1), fleet.stop.set()), daemon=True
            ).start()
            asyncio.run(fleet.run())
            result = dict(fleet.summary, state="stopped")
    except Exception as exc:
        if fleet:
            result = dict(fleet.summary)
        result.update(
            state="error",
            error=str(exc)
            if isinstance(exc, ValueError)
            else "Simulation could not start. Check its local configuration and inventory cache.",
        )
        print(json.dumps(result), flush=True)
        return 1
    print(json.dumps(result), flush=True)
    return 0
