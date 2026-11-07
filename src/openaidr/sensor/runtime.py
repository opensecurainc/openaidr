import copy
from contextlib import contextmanager
import json
import logging
import os
import random
import sqlite3
import threading
import time
import uuid
from pathlib import Path
import httpx
from openaidr.build_info import for_version
from openaidr.core.cloud_protection import project as cloud_protection
from openaidr.core.event import new_id, now
from openaidr.core.protocol import HOOK_WORK_TIMEOUT_SECONDS, default_sensor_config, normalize_sensor_config
from openaidr.core.redact import is_secret_key, redact_event, redact_string
from .config import Config, capture_overrides, is_root
from openaidr.core.files import atomic_write
from openaidr.core.enrollment import validate_server_url
from .tls import client_options, same_origin, validate_ca_certificate
from . import network_proxy
from . import hostinfo, hook_runtime, hooks, service
from .collectors import Collector, Offsets
from .spool import Spool
from .health import HealthReporter
from .telemetry import Telemetry, settings as telemetry_settings
from .inventory_service import InventoryService, settings as inventory_settings
from .updates import UpdateChecker
from .capture import CaptureCoordinator
from .metrics import ProcessMetrics
from . import uploads

NOT_ENROLLED = (
    "sensor is not enrolled; run: openaidr enroll --server URL --token TOKEN"
)

HOOK_CONCURRENCY = 8


def _discard_policy_rules(response):
    """Keep only backend version metadata from older control-plane replies."""
    policy = response.pop("policy", None)
    version = response.pop("policy_version", policy.get("version") if isinstance(policy, dict) else None)
    if type(version) is int and version >= 0:
        response["policy_version"] = version


def discard_policy_cache(config):
    """Remove unscoped old rules after a new enrollment identity is saved."""
    try:
        (Path(config["data_dir"]) / "policy.json").unlink(missing_ok=True)
    except OSError as exc:
        logging.warning("enrollment saved; obsolete policy cache could not be removed: %s", exc)


class HookClientPool:
    """Share hook connections without holding the heartbeat lock during I/O."""

    def __init__(self):
        self.lock = threading.Lock()
        self.key, self.current = None, None
        self.users = {}
        self.closed = False

    @contextmanager
    def acquire(self, config, deadline):
        key = tuple(config.get(name) for name in (
            "server_url", "tenant_id", "sensor_id", "auth_mode", "sensor_token",
            "credential_generation", "ca_cert", "client_cert", "client_key",
        )) + (json.dumps(config.get("network"), sort_keys=True, default=str),)
        # Trust and key files can also be replaced at the same configured path.
        for name in ("ca_cert", "client_cert", "client_key"):
            path = config.get(name)
            if path and (name == "ca_cert" or config.get("auth_mode") == "mtls"):
                stat = Path(path).expanduser().stat()
                key += (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        client = replacement = retired = None
        try:
            while client is None:
                if not self.lock.acquire(timeout=max(0, deadline - time.monotonic())):
                    raise TimeoutError("deadline_expired")
                try:
                    if self.closed or time.monotonic() >= deadline:
                        raise TimeoutError("hook transport unavailable")
                    if key != self.key and replacement is not None:
                        previous = self.current
                        self.key, self.current = key, replacement
                        self.users[replacement] = 0
                        replacement = None
                        if previous is not None and self.users[previous] == 0:
                            del self.users[previous]
                            retired = previous
                    if key == self.key:
                        client = self.current
                        self.users[client] += 1
                finally:
                    self.lock.release()
                if client is None:
                    # Loading certificate files must not hold up other replies
                    # or shutdown. Concurrent initializers share the first pool.
                    limits = httpx.Limits(max_connections=HOOK_CONCURRENCY,
                                          max_keepalive_connections=4, keepalive_expiry=120)
                    replacement = httpx.Client(
                        timeout=HOOK_WORK_TIMEOUT_SECONDS, limits=limits,
                        **client_options(config, limits=limits),
                    )
            if replacement is not None:
                replacement.close()
                replacement = None
            if retired is not None:
                retired.close()
            yield client
        finally:
            if replacement is not None:
                replacement.close()
            if client is not None:
                with self.lock:
                    self.users[client] -= 1
                    close = self.users[client] == 0 and (self.closed or client is not self.current)
                    if close:
                        del self.users[client]
                if close:
                    client.close()

    def close(self):
        with self.lock:
            self.closed = True
            idle = [client for client, users in self.users.items() if users == 0]
            for client in idle:
                del self.users[client]
        # In-flight requests release retired clients after consuming their reply.
        for client in idle:
            client.close()


def hook_actions(request, capture):
    """Project permitted evidence and report gaps to the backend classifier."""
    category = {"UserPromptSubmit": "prompt_text", "PreToolUse": "tool_input",
                "PostToolUse": "tool_output", "PostToolUseFailure": "tool_output"}[request["hook_event"]]
    if not capture.get(category):
        return "capture_disabled", []
    if request["availability"] not in ("available", "unsupported_boundary"):
        return request["availability"], []
    actions, gaps = [], set()
    limit = capture.get("max_text_bytes") or 16384

    def clean(value):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if capture.get("redact") and is_secret_key(key):
                    gaps.add("content_redacted")
                    result[key] = "[REDACTED]"
                else:
                    result[key] = clean(item)
            return result
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, str):
            if capture.get("redact"):
                value, names = redact_string(value)
                if names:
                    gaps.add("content_redacted")
            if len(value.encode()) > limit:
                gaps.add("content_truncated")
                value = value.encode()[:limit].decode("utf-8", errors="ignore")
            return value
        return value

    for event in request["actions"]:
        action = {"kind": event["kind"], "agent": {"product": request["product"]}}
        for section, keys in (
            ("session", ("id", "cwd")), ("tool", ("name", "input", "output", "call_id", "is_error")),
            ("command", ("text", "cwd", "exit_code")), ("file", ("path", "operation")),
            ("network", ("host", "url")),
        ):
            if section in event:
                action[section] = {key: copy.deepcopy(event[section][key]) for key in keys if key in event[section]}
        if "text" in event:
            action["text"] = event["text"]
        if not capture.get("tool_input"):
            for section in ("command", "file", "network"):
                action.pop(section, None)
            action.get("session", {}).pop("cwd", None)
        redact_event(action, capture)
        if action.pop("redacted", False):
            gaps.add("content_redacted")
        if action.pop("truncated", False):
            gaps.add("content_truncated")
        actions.append(clean(action))
    if len(actions) > 128 or len(json.dumps(actions).encode()) > 60 << 10:
        return "content_truncated", []
    if gaps:
        return ("content_truncated" if "content_truncated" in gaps else "content_redacted"), actions
    return request["availability"], actions


class Client:
    def __init__(
        self,
        url,
        token="",
        version="dev",
        ca_cert=None,
        ca_certificate=None,
        *,
        auth_mode="bearer",
        client_cert=None,
        client_key=None,
        tenant_id="",
        sensor_id="",
        network=None,
    ):
        self.url = url.rstrip("/")
        self.lock = threading.RLock()
        self.on_auth_failure = None
        self.auth_mode = auth_mode
        self.credential_generation = None
        options = client_options(
            dict(
                server_url=url,
                sensor_token=token,
                ca_cert=ca_cert,
                auth_mode=auth_mode,
                client_cert=client_cert,
                client_key=client_key,
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                network=network,
            ),
            ca_certificate,
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "openaidr/" + version,
            **options.pop("headers"),
        }
        self.http = httpx.Client(timeout=30, headers=headers, **options)

    @classmethod
    def from_config(cls, config, version="dev"):
        if config.get("connection_mode") in ("free", "api_key"):
            from .free_runtime import FreeClient

            return FreeClient(config)
        client = cls(
            config["server_url"],
            config.get("sensor_token", ""),
            version,
            ca_cert=config.get("ca_cert"),
            auth_mode=config.get("auth_mode", "bearer"),
            client_cert=config.get("client_cert"),
            client_key=config.get("client_key"),
            tenant_id=config.get("tenant_id", ""),
            sensor_id=config.get("sensor_id", ""),
            network=config.get("network"),
        )
        client.credential_generation = config.get("credential_generation")
        return client

    def post(self, path, body, *, timeout=None):
        with self.lock:
            options = {"timeout": timeout} if timeout is not None else {}
            url = self.url + "/ingest/v1/" + path
            if path in uploads.INGEST_PATHS:
                content = httpx.Request("POST", url, json=body).content
                response = uploads.post(self.http, url, content,
                                        chunk_url=self.url + "/ingest/v1/uploads/" + path,
                                        headers={"Content-Type": "application/json"}, **options)
            else:
                response = self.http.post(url, json=body, **options)
            if (
                self.auth_mode == "mtls"
                and response.status_code in (401, 403)
                and self.on_auth_failure
            ):
                self.on_auth_failure()
            response.raise_for_status()
        return response.json() if response.content.strip() else {}

    def close(self):
        with self.lock:
            self.http.close()

    def refresh(self, config, version="dev"):
        replacement = Client.from_config(config, version)
        with self.lock:
            previous = self.http
            self.http, self.url, self.auth_mode = (
                replacement.http,
                replacement.url,
                replacement.auth_mode,
            )
            self.credential_generation = replacement.credential_generation
            previous.close()


def check_reenrollment(config):
    """Keep queued events attached to their original tenant identity."""
    if not config.enrolled():
        return
    try:
        hooks.local_request(config, "GET", "/v1/status")
    except Exception:
        pass
    else:
        raise ValueError(
            "Stop the current sensor service before re-enrolling. "
            "Deliver any queued events to the current server first; re-enrollment never deletes queued data."
        )
    directory = Path(config["data_dir"])
    database = directory / "telemetry.sqlite3"
    if database.exists():
        try:
            connection = sqlite3.connect(
                database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2
            )
            try:
                pending = connection.execute("SELECT COUNT(*) FROM exports").fetchone()[
                    0
                ]
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise ValueError(
                "Cannot verify that the telemetry queue is empty. "
                "Repair and drain the existing queue before re-enrolling; no queued data was changed."
            ) from exc
        if pending:
            raise ValueError(
                f"Cannot re-enroll with {pending} pending telemetry exports. "
                "Keep the current connection until the uploads finish, then try again. No queued data was changed."
            )
    spool_path = directory / "spool"
    if spool_path.exists():
        spool = Spool(spool_path)
        try:
            pending = spool.depth
        finally:
            spool.close()
        if pending:
            raise ValueError(
                f"Cannot re-enroll with {pending} pending legacy events. "
                "Keep the current connection until the uploads finish, then try again. No queued data was changed."
            )


def enroll(
    config,
    server,
    token,
    label="",
    host_kind="",
    version="dev",
    ca_certificate=None,
    *,
    auth_mode="bearer",
    tenant_id="",
):
    config.validate()
    if auth_mode not in ("bearer", "mtls"):
        raise ValueError("auth_mode must be bearer or mtls")
    device = hostinfo.device()
    if auth_mode == "mtls":
        try:
            from . import credentials
        except ImportError as exc:
            raise ValueError(
                "certificate enrollment requires the openaidr[device] extra"
            ) from exc
        metadata = dict(
            hostinfo.current(),
            sensor_version=version,
            label=label,
            host_kind=host_kind or config["host_kind"],
            policy_delivery="backend",
            device=device,
        )
        if metadata["host_kind"] not in ("workstation", "server"):
            raise ValueError("host_kind must be workstation or server")
        result = credentials.enroll(
            config,
            server,
            token,
            tenant_id,
            metadata,
            ca_certificate=ca_certificate,
            version=version,
        )
        discard_policy_cache(config)
        _discard_policy_rules(result)
        try:
            atomic_write(
                Path(config["data_dir"]) / "server-config.json",
                json.dumps(normalize_sensor_config(result.get("config", {}))),
            )
        except (OSError, ValueError, TypeError) as exc:
            logging.warning(
                "enrollment saved; control-plane cache will refresh: %s", exc
            )
        return result
    if config.get("auth_mode", "bearer") == "mtls":
        raise ValueError(
            "mTLS enrollment cannot fall back to bearer; use credential recovery"
        )
    server = validate_server_url(server)
    check_reenrollment(config)
    host_kind = host_kind or config["host_kind"]
    if host_kind not in ("workstation", "server"):
        raise ValueError("host_kind must be workstation or server")
    if ca_certificate is not None and not isinstance(ca_certificate, str):
        raise ValueError("CA certificate must be PEM text")
    supplied_ca = validate_ca_certificate(ca_certificate) if ca_certificate else None
    inherited_ca = (
        config.get("ca_cert")
        if ca_certificate is None and same_origin(config.get("server_url", ""), server)
        else None
    )
    client = Client(
        server, version=version, ca_cert=inherited_ca, ca_certificate=supplied_ca,
        network=config.get("network"),
    )
    try:
        response = client.post(
            "enroll",
            dict(
                hostinfo.current(),
                enrollment_token=token,
                sensor_version=version,
                host_kind=host_kind,
                label=label,
                policy_delivery="backend",
                device=device,
            ),
        )
    finally:
        client.close()
    if not response.get("sensor_id") or not response.get("sensor_token"):
        raise ValueError("server response missing sensor identity")
    if tenant_id and response.get("tenant", {}).get("id") != tenant_id:
        raise ValueError("Enrollment response does not match the organization you confirmed")
    # Prepare every change before committing local identity/trust. Failed TLS,
    # authentication, and malformed enrollment responses leave existing files
    # and the caller's config object unchanged.
    server_config = normalize_sensor_config(response.get("config", {}))
    _discard_policy_rules(response)
    candidate = Config(config.path, **copy.deepcopy(dict(config)))
    candidate.pop("connection_mode", None)
    candidate.update(
        server_url=server,
        sensor_id=response["sensor_id"],
        sensor_token=response["sensor_token"],
        host_kind=host_kind,
    )
    # Older bearer enrollments did not retain the authenticated tenant identity.
    # Do not carry a previous tenant across re-enrollment if an old receiver
    # omits it; managed bootstrap can resolve that identity before registration.
    received_tenant = response.get("tenant", {}).get("id")
    if received_tenant:
        candidate["tenant_id"] = str(uuid.UUID(received_tenant))
    else:
        candidate.pop("tenant_id", None)
    if label:
        candidate["label"] = label
    trust_path = (Path(config["data_dir"]) / "ca-cert.pem").resolve()
    if supplied_ca:
        candidate["ca_cert"] = str(trust_path)
    elif inherited_ca:
        candidate["ca_cert"] = str(Path(inherited_ca).expanduser().resolve())
    else:
        candidate.pop("ca_cert", None)
    old_trust = trust_path.read_bytes() if supplied_ca and trust_path.exists() else None
    try:
        if supplied_ca:
            atomic_write(trust_path, supplied_ca)
        candidate.save()
    except Exception:
        if supplied_ca:
            if old_trust is None:
                trust_path.unlink(missing_ok=True)
            else:
                atomic_write(trust_path, old_trust.decode("ascii"))
        raise
    config.clear()
    config.update(candidate)
    discard_policy_cache(config)
    # These settings refresh on the next heartbeat; inability to cache must not
    # misreport a successfully persisted enrollment as a failed enrollment.
    try:
        atomic_write(
            Path(config["data_dir"]) / "server-config.json", json.dumps(server_config)
        )
    except (OSError, ValueError, TypeError) as exc:
        logging.warning("enrollment saved; control-plane cache will refresh: %s", exc)
    return response


class Sensor:
    def __init__(self, config, version="dev"):
        config.validate()
        inventory_settings(config)
        if not config.enrolled():
            raise ValueError(NOT_ENROLLED)
        self.client = Client.from_config(config, version)
        self.config, self.version, self.host = config, version, hostinfo.current()
        self.device = hostinfo.device()
        self.tenant_name = ""
        self.cloud_protection = None
        self.started, self.started_at = time.monotonic(), now()
        self.lock, self.wake = threading.RLock(), threading.Event()
        # Set by emit so spooled events ship at once instead of waiting a flush interval.
        self.ship_wake = threading.Event()
        self.disabled, self.dropped, self.policy_version = False, 0, 0
        directory = Path(config["data_dir"])
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.updates = UpdateChecker(config)
        try:
            self.server_config = normalize_sensor_config(
                json.loads((directory / "server-config.json").read_text())
            )
        except (OSError, ValueError):
            self.server_config = default_sensor_config()
        if config.get("connection_mode") in ("free", "api_key"):
            self.server_config = default_sensor_config()
        self.capture = capture_overrides(
            self.server_config["capture"], config.get("capture")
        )
        self.spool = Spool(directory / "spool")
        self.managed_capture = CaptureCoordinator(config)
        self.pending_hook_decisions = hook_runtime.PendingDecisions(
            self.delivered_hook_decision, failed=self.failed_hook_decision
        )
        self.hook_slots = threading.BoundedSemaphore(HOOK_CONCURRENCY)
        self.hook_clients = HookClientPool()
        self.hook_receipts_lock = threading.Lock()
        self.offsets = Offsets(directory / "offsets.json")
        self.collectors = []
        cfg = config.get("collectors") or {}
        for product in ("claude-code", "codex-cli", "gemini-cli", "cowork"):
            options = cfg.get(product.replace("-", "_")) or {}
            if options.get("enabled", product == "cowork"):
                self.collectors.append(
                    Collector(
                        product,
                        hostinfo.homes(),
                        options.get("paths", []),
                        self.offsets,
                        cfg.get("backfill", False),
                        self.emit,
                    )
                )
        self.hooks = hooks.HookServer(
            config["listen"],
            directory / "sensor.sock",
            self.emit,
            self.status,
            self.host,
            {
                product: not (cfg.get(product.replace("-", "_")) or {}).get(
                    "enabled", False
                )
                for product in hooks.PRODUCTS.values()
            },
            check=self.check_hook,
            disconnected=self.pending_hook_decisions.record_receipt,
            # Loopback TCP is open to every local account. A per-user sensor
            # requires its private token; a root service serves all accounts.
            token=(
                telemetry_settings(config, persist_token=True)["local_token"]
                if os.name == "nt" or not is_root() else None
            ),
        )
        self.ship = dict(
            shipped=0,
            duplicates=0,
            rejected=0,
            failures=0,
            last_ship_at=None,
            last_error="",
            paused=False,
            batch_max=self.server_config["batch_max_events"],
        )
        self.last_heartbeat, self.heartbeat_error = None, ""
        self.health = HealthReporter()
        self.metrics = ProcessMetrics()
        self.telemetry = (
            Telemetry(
                config, on_auth_failure=self.pause_device, paused=lambda: self.disabled,
                capture=lambda: copy.deepcopy(self.capture), coordinator=self.managed_capture,
            )
            if telemetry_settings(config)["enabled"]
            else None
        )
        self.client.on_auth_failure = self.pause_device
        from .project_metadata import Recovery

        self.project_metadata = Recovery(
            config, lambda: copy.deepcopy(self.capture) if not self.disabled else None,
            self.managed_capture,
        )
        local_inventory = config.get("connection_mode") in ("free", "api_key")
        self.inventory = InventoryService(
            config,
            self.client,
            paused=lambda: self.disabled or (not local_inventory and self.last_heartbeat is None),
        )
        self.component_inventory = InventoryService(
            config,
            self.client,
            paused=lambda: self.disabled or (not local_inventory and self.last_heartbeat is None),
            components=True,
        )
        from .posture_assessments import Worker

        self.posture = Worker(config, paused=lambda: self.disabled)

    def agent_homes(self):
        """Agent directories recorded since this process started.

        CLI commands record ``hooks.homes`` in the config file while the
        service keeps running, so it is read again at each use.
        """
        try:
            homes = (Config.load(self.config.path).get("hooks") or {}).get("homes")
        except Exception:
            homes = (self.config.get("hooks") or {}).get("homes")
        return {"hooks": {"homes": homes}} if isinstance(homes, dict) else {}

    def pause_device(self):
        self.disabled = True
        self.ship["paused"] = True
        if self.telemetry:
            self.telemetry.auth_denied = True

    def emit(self, event):
        event = copy.deepcopy(event)
        with self.lock:
            if self.disabled and (
                event.get("kind") != "sensor" or "evidence" in event
            ):
                self.dropped += 1
                return
            capture = copy.deepcopy(self.capture)
        evidence = event.get("evidence")
        if (
            isinstance(evidence, dict)
            and evidence.get("version") == 1
            and isinstance(evidence.get("observation_id"), str)
        ):
            identity = json.dumps(
                ["openaidr-evidence-v1", self.config["sensor_id"], evidence["observation_id"]],
                separators=(",", ":"),
            )
            event.setdefault("id", str(uuid.uuid5(uuid.NAMESPACE_URL, identity)))
        else:
            event.setdefault("id", new_id())
        event.setdefault("observed_at", now())
        event.setdefault("time", now())
        event["host"] = dict(
            self.host, **{k: v for k, v in event.get("host", {}).items() if v}
        )
        event.setdefault("agent", {}).setdefault("product", "unknown")
        event.setdefault("source", {}).setdefault("collector", "sensor")
        pending = event.get("kind") == "hook.decision" and event.get("hook", {}).get("delivery") == "pending"
        sink = self.pending_hook_decisions.stage if pending else self.spool.append
        if self.managed_capture.emit(event, capture, sink) and not pending:
            self.ship_wake.set()

    def delivered_hook_decision(self, event):
        self.emit(event)
        self.hooks.delivered(event)
        self.hook_delivery(event, "delivered")

    def failed_hook_decision(self, event):
        self.hook_delivery(event, event["hook"]["delivery"])
        hook = event["hook"]
        if hook.get("timeout_owner") in ("agent", "sensor"):
            # A launcher may stop before recording its outcome. Share its run
            # ID so a later receipt cannot double-count the sensor's evidence.
            self.emit(hook_runtime.measurement(
                self.config["sensor_id"], event["agent"]["product"], hook["hook_event"],
                hook["execution_id"], None, event["time"],
                failure_reason=hook.get("failure_reason") or "delivery_failed",
            ))

    def hook_delivery(self, event, status):
        hook = event["hook"]
        if not hook.get("request_id"):
            return
        # Only called by the background receipt collector. The ordinary bounded
        # spool retries uploads, including after a restart or network outage.
        self.emit({
            "id": str(uuid.uuid5(uuid.UUID(hook["request_id"]), "hook-delivery")),
            "kind": "sensor", "agent": event["agent"],
            "source": {"collector": "hook-delivery", "hook_request_id": hook["request_id"]},
            "hook": {"delivery_status": status,
                     "delivered_decision": hook["decision"] if status == "delivered" else "allow"},
        })

    def check_hook(self, request, deadline):
        """Installed hooks use backend decisions without waiting on shipping."""
        if self.disabled:
            raise ValueError("backend_unavailable")
        if not self.hook_slots.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("deadline_expired")
        try:
            with self.lock:
                capture, config = copy.deepcopy(self.capture), copy.deepcopy(self.config)
            # Never export a native observation belonging to a managed launch
            # through the ordinary endpoint, even if an inherited env was lost.
            if self.managed_capture.route(request["product"], request["session_id"]) is not None:
                raise ValueError("managed_session")
            availability, actions = hook_actions(request, capture)
            # Launcher IDs only correlate short-lived receipts. Native process
            # IDs can repeat across restarts and are not persistent request IDs.
            ident = request.get("request_id") or str(uuid.uuid4())
            body = {key: request[key] for key in ("product", "hook_event", "session_id", "tool_call_id")}
            path_home = request.get("path_home")
            if (availability == "available" and capture.get("tool_input")
                    and isinstance(path_home, str) and path_home
                    and any(action.get("file", {}).get("path") for action in actions)):
                if len(path_home) > 4096 or len(path_home.encode()) > (capture.get("max_text_bytes") or 16384):
                    availability, actions = "content_truncated", []
                elif capture.get("redact") and redact_string(path_home)[0] != path_home:
                    availability, actions = "content_redacted", []
                else:
                    body["path_home"] = path_home
            body.update(request_id=ident, availability=availability, actions=actions)
            body["control_supported"] = request["availability"] != "unsupported_boundary"
            if config.get("connection_mode") in ("free", "api_key"):
                # A check can fail on local evidence or its deadline. Only the
                # heartbeat's service status determines cloud availability.
                return self.client.check(body, deadline)
            with self.hook_clients.acquire(config, deadline) as client:
                reserve = 0 if request.get("timeout_owner") in ("agent", "sensor") else 0.05
                remaining = deadline - time.monotonic() - reserve
                if remaining <= 0:
                    raise TimeoutError("deadline_expired")
                # Older backends require this field. Current backends ignore it.
                body["timeout_ms"] = max(1, min(1800, int(remaining * 1000)))
                with client.stream("POST", config["server_url"] + "/ingest/v1/hook-checks",
                                   json=body, timeout=remaining) as response:
                    response.raise_for_status()
                    data = bytearray()
                    for part in response.iter_bytes():
                        data.extend(part)
                        if len(data) > 64 << 10 or time.monotonic() >= deadline:
                            raise TimeoutError("hook response unavailable")
                    result = json.loads(data)
            if time.monotonic() >= deadline:
                raise TimeoutError("deadline_expired")
            if not isinstance(result, dict) or result.get("request_id") != ident:
                raise ValueError("invalid_backend_response")
            return result
        except httpx.TimeoutException as exc:
            raise TimeoutError("deadline_expired") from exc
        finally:
            self.hook_slots.release()

    def status(self):
        # Read readiness before the administrative state. A heartbeat that
        # completes during this snapshot must not expose the earlier state as ready.
        last_heartbeat = self.last_heartbeat
        hook_state = hooks.status(config=self.agent_homes())
        return dict(
            sensor_id=self.config["sensor_id"],
            connection_mode=self.config.get("connection_mode", "organization"),
            version=self.version,
            build=for_version(self.version),
            server_url=self.config["server_url"],
            tenant_name=self.tenant_name,
            cloud_protection=cloud_protection(self.cloud_protection),
            ca_cert=self.config.get("ca_cert", ""),
            custom_ca=bool(self.config.get("ca_cert")),
            network_proxy=network_proxy.public_status(self.config, check_password=False),
            hostname=self.host["hostname"],
            user=self.host["user"],
            device=self.device,
            started_at=self.started_at,
            uptime_s=int(time.monotonic() - self.started),
            disabled=self.disabled,
            collectors=[c.status() for c in self.collectors],
            queue_depth=self.spool.depth,
            spool_dropped=self.spool.dropped,
            dropped_while_disabled=self.dropped,
            policy_delivery="backend",
            policy_version=self.policy_version,
            hook_installed=any(state["installed"] for state in hook_state.values()),
            hooks_installed=hook_state,
            hooks=copy.deepcopy(self.hooks.stats),
            ship=copy.deepcopy(self.ship),
            last_heartbeat_at=last_heartbeat,
            heartbeat_error=self.heartbeat_error,
            capture=self.capture,
            telemetry=self.telemetry.status() if self.telemetry else {"enabled": False},
            inventory=self.inventory.status(),
            component_inventory=self.component_inventory.status(),
            update=dict(self.updates.result),
        )

    def apply(self, response):
        _discard_policy_rules(response)
        version = response.get("policy_version")
        if type(version) is int and version >= 0:
            self.policy_version = version
        if response.get("config") is not None:
            with self.lock:
                self.server_config = normalize_sensor_config(response["config"])
                self.capture = capture_overrides(
                    self.server_config["capture"], self.config.get("capture")
                )
                atomic_write(
                    Path(self.config["data_dir"]) / "server-config.json",
                    json.dumps(self.server_config),
                )
        tenant_name = response.get("tenant_name")
        self.tenant_name = tenant_name if isinstance(tenant_name, str) else ""
        self.cloud_protection = cloud_protection(response.get("cloud_protection", response.get("cloud_credit")))
        self.disabled = bool(response.get("disabled"))
        acknowledgements = []
        homes = self.agent_homes()
        for command in response.get("commands", []):
            ack = {"status": "applied"}
            try:
                typ = command["type"]
                if typ in ("disable", "enable"):
                    self.disabled = typ == "disable"
                elif typ == "refresh_policy":
                    self.wake.set()
                elif typ in ("install_hook", "uninstall_hook"):
                    agent = (command.get("params") or {}).get("agent") or "claude"
                    agents = list(hooks.AGENTS) if agent == "all" else [agent]
                    if any(name not in hooks.AGENTS for name in agents):
                        raise ValueError("unknown hook agent " + str(agent))
                    for name in agents:
                        if typ == "install_hook":
                            # The staged console sensor, as setup uses: this
                            # process may be the windowless Windows build,
                            # whose output goes to its log, not to the agent.
                            hooks.install(
                                hooks.settings_path(name, homes), service.hook_executable(), name,
                                config_path=self.config.path, explicit=True,
                                config_toml=hooks.codex_config_path(homes),
                            )
                        else:
                            hooks.uninstall(hooks.settings_path(name, homes), name,
                                            hooks.codex_config_path(homes),
                                            config_path=self.config.path)
                        hooks.set_opt_out(self.config, name, typ == "uninstall_hook")
                else:
                    raise ValueError("unknown command type " + typ)
            except Exception as exc:
                ack = {"status": "failed", "message": str(exc)}
            acknowledgements.append((command["id"], ack))
        return acknowledgements

    def collect_hook_receipts(self):
        with self.hook_receipts_lock:
            directories = hook_runtime.registered_directories(self.config)
            homes = self.agent_homes()
            directories.update(hook_runtime.directory(hooks.settings_path(agent, homes))
                               for agent in hooks.AGENTS)
            for directory in directories:
                hook_runtime.collect(directory, self.emit, sensor_id=self.config["sensor_id"],
                                     complete=self.pending_hook_decisions.complete)
            self.pending_hook_decisions.flush()

    def hook_receipts_loop(self, stop):
        while not stop.is_set():
            try:
                self.collect_hook_receipts()
            except Exception:
                pass
            stop.wait(0.25)

    def heartbeat_once(self):
        try:
            self.collect_hook_receipts()
            if self.config.get("auth_mode") == "mtls" and self.config.get(
                "credential_generation"
            ):
                try:
                    from .credentials import maintain

                    maintain(self.config, self.version)
                    if self.client.credential_generation != self.config.get(
                        "credential_generation"
                    ):
                        self.client.refresh(self.config, self.version)
                    if (
                        self.telemetry
                        and self.telemetry.credential_generation
                        != self.config.get("credential_generation")
                    ):
                        self.telemetry.refresh()
                except Exception as exc:
                    logging.warning(
                        "credential maintenance failed; existing queues and credentials retained: %s",
                        exc,
                    )
            body = dict(
                sensor_id=self.config["sensor_id"],
                sensor_version=self.version,
                uptime_s=int(time.monotonic() - self.started),
                collectors=[c.status() for c in self.collectors],
                queue_depth=self.spool.depth,
                policy_version=self.policy_version,
                policy_delivery="backend",
                hook_installed=any(
                    state["installed"] for state in hooks.status(config=self.agent_homes()).values()
                ),
                device=self.device,
            )
            signed_in_user = hostinfo.signed_in_user()
            if signed_in_user is not None:
                body["signed_in_user"] = signed_in_user
            if self.telemetry is not None:
                telemetry = self.telemetry.status()
                body["telemetry_queue_depth"] = telemetry["queue_depth"]
            else:
                telemetry = {}
            body["health_report"] = self.health.report(
                activity=self.ship.copy(), depth=body["queue_depth"],
                dropped=self.spool.dropped, telemetry=telemetry,
                collectors=body["collectors"], disabled=self.disabled,
            )
            body.update(self.metrics.sample())
            try:
                metadata = self.project_metadata.report()
            except Exception:
                metadata = None
            if metadata is not None:
                body["project_metadata"] = metadata
            response = self.client.post("heartbeat", body)
            acknowledgements = self.apply(response)
            self.project_metadata.accept(metadata, response.get("project_metadata"))
            self.last_heartbeat, self.heartbeat_error = now(), ""
            for command_id, ack in acknowledgements:
                self.client.post("commands/" + command_id + "/ack", ack)
            if self.config.get("auth_mode") == "mtls" and not self.disabled:
                self.ship["paused"] = False
                self.ship_wake.set()
                if self.telemetry:
                    self.telemetry.auth_denied = False
                    self.telemetry.wake.set()
        except Exception as exc:
            self.heartbeat_error = str(exc)
            if self.config.get("connection_mode") in ("free", "api_key"):
                self.cloud_protection = {"state": "unavailable", "checked_at": time.time()}
            logging.warning("heartbeat failed: %s", exc)

    def heartbeat_loop(self, stop):
        while not stop.is_set():
            self.heartbeat_once()
            if self.config.get("connection_mode") not in ("free", "api_key"):
                self.updates.check_due(self.client)
            deadline = time.monotonic() + self.server_config["heartbeat_interval_s"]
            while not stop.is_set() and time.monotonic() < deadline:
                if self.wake.wait(min(0.5, max(0, deadline - time.monotonic()))):
                    self.wake.clear()
                    break

    def ship_loop(self, stop):
        backoff, successes = 1, 0
        while not stop.is_set():
            # Ship as soon as something is spooled rather than once per flush
            # interval, so a hook event reaches the backend within about a
            # second of the agent action. The short pause after a wake lets a
            # burst of events from one turn travel in one batch.
            if self.ship_wake.wait(self.server_config["flush_interval_s"]):
                self.ship_wake.clear()
                if stop.wait(0.1):
                    break
            elif stop.is_set():
                break
            while not stop.is_set():
                if self.config.get("auth_mode") == "mtls" and self.disabled:
                    break
                self.ship["batch_max"] = min(
                    self.ship["batch_max"], self.server_config["batch_max_events"]
                )
                batch = self.spool.read(self.ship["batch_max"])
                if batch is None:
                    break
                if self.telemetry:
                    self.telemetry.estimate_hooks(batch["events"])
                try:
                    result = self.client.post(
                        "events",
                        dict(
                            schema_version=1,
                            sensor_id=self.config["sensor_id"],
                            sent_at=now(),
                            events=batch["events"],
                        ),
                    )
                    self.spool.ack(batch)
                    for key, value in (
                        ("shipped", result.get("accepted", 0)),
                        ("duplicates", result.get("duplicates", 0)),
                        ("rejected", len(result.get("rejected") or [])),
                    ):
                        self.ship[key] += value
                    self.ship.update(last_ship_at=now(), last_error="", paused=False)
                    backoff, successes = 1, successes + 1
                    if successes >= 10:
                        self.ship["batch_max"] = min(
                            self.ship["batch_max"] * 2,
                            self.server_config["batch_max_events"],
                        )
                        successes = 0
                except Exception as exc:
                    self.ship["failures"] += 1
                    self.ship["last_error"] = str(exc)
                    code = (
                        exc.response.status_code
                        if isinstance(exc, httpx.HTTPStatusError)
                        else 0
                    )
                    if code == 413:
                        self.ship["batch_max"] = max(1, self.ship["batch_max"] // 2)
                        successes = 0
                        delay = 1 if self.ship["batch_max"] == 1 else 0
                    elif code in (401, 403, 429):
                        delay = {401: 300, 403: 60, 429: 30}[code]
                        self.ship["paused"] = code == 403
                    else:
                        if isinstance(exc, httpx.ReadTimeout):
                            # The server may have committed part of the batch.
                            # Retain every unacknowledged ID, but reduce repeat
                            # work until uploads fit within the response budget.
                            self.ship["batch_max"] = max(
                                1, min(self.ship["batch_max"], len(batch["events"])) // 2
                            )
                            successes = 0
                        delay = backoff + random.random() * backoff / 5
                        backoff = min(300, backoff * 2)
                    if stop.wait(delay):
                        break

    def run(self, stop=None):
        stop = stop or threading.Event()
        errors = []

        def worker(fn):
            try:
                fn(stop)
            except BaseException as exc:
                errors.append(exc)
                stop.set()

        funcs = [self.hooks.run, self.ship_loop, self.heartbeat_loop, self.hook_receipts_loop] + [
            c.run for c in self.collectors
        ]
        funcs.append(self.project_metadata.run)
        if self.telemetry:
            funcs.extend([self.telemetry.receive, self.telemetry.forward,
                          lambda stop: self.telemetry.import_usage(stop, watch=True)])
        if self.inventory.options["enabled"]:
            funcs.append(self.inventory.run)
        if self.component_inventory.options["enabled"]:
            funcs.append(self.component_inventory.run)
        funcs.append(self.posture.run)
        threads = [
            threading.Thread(target=worker, args=(fn,), daemon=True) for fn in funcs
        ]
        for thread in threads:
            thread.start()
        self.emit(
            {
                "kind": "sensor",
                "text": "sensor started",
                "agent": {"product": "unknown", "version": self.version},
            }
        )
        stop.wait()
        self.wake.set()
        self.ship_wake.set()
        for thread in threads:
            thread.join(timeout=35)
        try:
            self.offsets.flush()
        except OSError as exc:
            for collector in self.collectors:
                collector.error = str(exc)
        self.spool.close()
        self.hook_clients.close()
        self.client.close()
        if self.telemetry:
            self.telemetry.close()
        if errors:
            raise errors[0]
